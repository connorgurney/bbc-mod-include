/* FIXME unescape_url is a hack atm. -- see if apache/apr provides this somewhere */

/* 
**  mod_ssi_setsplitvars.c -- Apache sample ssi_setsplitvars module
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_ssi_setsplitvars.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ssi_setsplitvars in as follows:
**
**    #   httpd.conf
**    LoadModule ssi_setsplitvars_module modules/mod_ssi_setsplitvars.so
**  
**  Written by Andre Breiler <andre.breiler@is.bbc.co.uk> 2004
**  
*/ 

#if defined DEBUG
#undef DEBUG
#define DEBUG(...) ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, \
                   ##__VA_ARGS__);
#else
#define DEBUG
#endif

#include "apr.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_user.h"
#include "apr_lib.h"
#include "apr_optional.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "mod_include.h"

module AP_MODULE_DECLARE_DATA ssi_setsplitvars_module;

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *ssi_setsplitvars_pfn_rih;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *ssi_setsplitvars_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *ssi_setsplitvars_pfn_ps;

/* copied and modified from main apache source */
static char x2c(const char *what)
{
    register char digit;

#if !APR_CHARSET_EBCDIC
    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
             : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
              : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
                                0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
    return (digit);
}

/* copied and modified from main apache source */
int unescape_url(char *url)
{
    char *x, *y;

    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%')
            *x = *y;
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                *x = '%';
            }
            else {
                *x = x2c(y + 1);
                y += 2;
            }
        }
    }
    *x = '\0';
    return OK;
}

/**
 * Check if string contains no denied chars for var names
 * @param var The variable name to check
 * @return 0 if the name contains not allowed chars otherwise != 0
 */
int is_unprivvar(char *var)
{
    int ok = 0;
    while (var != NULL && *var != '\0') {
        if ((*var <= 'A' || *var >= 'Z') && *var != '_') {
            ok = 1;
            break;
        }
        var++;
    }
    return ok;
}

static int handle_setsplitvars(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                               request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                               apr_bucket **inserted_head)
{
    apr_table_t *allow_table = NULL;
    int urldecode  = 0;
    int htmldecode = 0;
    char *tag      = NULL;
    char *tag_val  = NULL;
    char *var      = NULL;
    char *value    = NULL;
    apr_bucket *tmp_buck;
    char *ps;
    request_rec *sub = r->main;
    apr_pool_t *p = r->pool;
    char *separator = "=";
    char *delimiter = "&";

    /* we need to use the 'main' request pool to set notes as that is 
     * a notes lifetime
     */
    while (sub) {
        p = sub->pool;
        sub = sub->main;
    }

    *inserted_head = NULL;
    if (ctx->flags & FLAG_PRINTING) {
        while (1) {
            ssi_setsplitvars_pfn_gtv(ctx, &tag, &tag_val, htmldecode);
            /* FIXME what is 0 and 1 doing as it looks the same */
            if (tag_val == NULL) {
                return (tag == NULL) ? 0 : 1;
            }
            else if (!strcmp(tag, "value")) {
                ps = ssi_setsplitvars_pfn_ps(r, ctx, tag_val, NULL,
                                                MAX_STRING_LEN, 0);
                for(var = ps, value = NULL; *ps != '\0'; ps++) {
                    DEBUG("\"setsplitvars\" ps=\"%s\" : del=\"%s\" : sep=\"%s\"", ps, delimiter, separator);
                    if (strstr(ps, delimiter) == ps) {
                        *ps = '\0';
                        if (var != NULL && *var != '\0') {
                            if (value == NULL) {
                                value = "";
                            }
                            DEBUG("\"setsplitvars\" found %s=%s", var, value);
                            if (urldecode && (unescape_url(var) ||
                                unescape_url(value))) {
                                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                "urldecode failed %s",
                                r->filename);
                                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                                    *inserted_head);
                                return (-1);
                            }
                            if ((allow_table != NULL &&
                                 apr_table_get(allow_table, var)) ||
                                (!apr_table_get(r->subprocess_env, var) &&
                                 is_unprivvar(var))) {
                                DEBUG("\"setsplitvars\" setting %s=%s", var, value);
                                apr_table_set(r->subprocess_env, var,
                                              value);
                            }
                            /* FIXME complain if unable to set var ? */
                        }
                        var = ps + strlen(delimiter);
                        value = NULL;
                    }
                    else if (strstr(ps, separator) == ps) {
                        DEBUG("\"setsplitvars\" found separator");
                        *ps = '\0';
                        ps += strlen(separator) - 1;
                	value = ps + 1;
                    }
                    else if (urldecode  && *ps == '+') {
                        *ps = ' ';
                    }
                }
                /* FIXME last element has to go here */
                if (var != NULL && *var != '\0') {
                    if (value == NULL) {
                        value = "";
                    }
                    DEBUG("\"setsplitvars\" found %s=%s as last item", var, value);
                    if (urldecode && (unescape_url(var) ||
                        unescape_url(value))) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "urldecode failed %s",
                        r->filename);
                        CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                            *inserted_head);
                        return (-1);
                    }
                    /* set var only if not allready set and the name is
                       not an protected on */
                    if ((allow_table != NULL &&
                         apr_table_get(allow_table, var)) ||
                        (!apr_table_get(r->subprocess_env, var) &&
                         is_unprivvar(var))) {
                        DEBUG("\"setsplitvars\" setting %s=%s as last item", var, value);
                        apr_table_set(r->subprocess_env, var,
                                      value);
                    }
                    /* FIXME should it complain about vars allready set ? */
                }
            }
            else if (!strcmp(tag, "separator")) {
                if (value != (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "separator must precede value in setsplitvars directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                ps = ssi_setsplitvars_pfn_ps(r, ctx, tag_val, NULL, 
                                             MAX_STRING_LEN, 0);
                if (ps && ps[0] != '\0') {
                    separator = apr_pstrdup(p, ps);
                    DEBUG("\"setsplitvars\" found separator = \"%s\"",
                          separator);
                }
            }
            else if (!strcmp(tag, "delimiter")) {
                if (value != (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "delimiter must precede value in setsplitvars directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                ps = ssi_setsplitvars_pfn_ps(r, ctx, tag_val, NULL, 
                                             MAX_STRING_LEN, 0);
                if (ps && ps[0] != '\0') {
                    delimiter = apr_pstrdup(p, ps);
                    DEBUG("\"setsplitvars\" found delimiter = \"%s\"",
                          delimiter);
                }
            }
            else if (!strcmp(tag, "allow")) {
                if (value != (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "allow must precede value in setsplitvars directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                ps = ssi_setsplitvars_pfn_ps(r, ctx, tag_val, NULL, 
                                             MAX_STRING_LEN, 0);
                DEBUG("\"setsplitvars\" allowing var %s", ps);
                if (ps && ps[0] != '\0') {
                    if (allow_table == NULL) {
                        DEBUG("\"setsplitvars\" creating table for allowed vars");
                        allow_table = apr_table_make(p, 16);
                    }
                    apr_table_set(allow_table, ps, "1");
                }
            }
            else if (!strcmp(tag, "decoding")) {
                if (value != (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "decoding must precede value in setsplitvars directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                ps = ssi_setsplitvars_pfn_ps(r, ctx, tag_val, NULL, 
                                             MAX_STRING_LEN, 0);
                if (!strcmp(ps, "url")) {
                    urldecode = 1;
                    DEBUG("\"setsplitvars\" sitching to urldecode");
                }
                else if (!strcmp(ps, "entity")) {
                    htmldecode = 1;
                    DEBUG("\"setsplitvars\" sitching to htmldecode");
                }
                else if (!strcmp(ps, "url_entity")) {
                    urldecode = 1;
                    htmldecode = 1;
                    DEBUG("\"setsplitvars\" sitching to url+htmldecode");
                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "decoding \"%s\" is invalid it must be url,entity,url_entity in \"%s\"",
                           ps, r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "Invalid tag \"%s\" for ssi setsplitvars directive in %s",
                             tag, r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                return -1;
            }
        }
    }
    return 0;
}

static int ssi_setsplitvars_post_config(apr_pool_t *p, apr_pool_t *plog,
                                        apr_pool_t *ptemp, server_rec *s)
{
    ssi_setsplitvars_pfn_rih = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    ssi_setsplitvars_pfn_gtv = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    ssi_setsplitvars_pfn_ps  = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);

    if ((ssi_setsplitvars_pfn_rih) && (ssi_setsplitvars_pfn_gtv) &&
        (ssi_setsplitvars_pfn_ps)) {
        ssi_setsplitvars_pfn_rih("setsplitvars", handle_setsplitvars);
        DEBUG("\"setsplitvars\" registered as ssi tag");
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "\"setsplitvars\" failed to register as ssi tag");
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const prereq[] = { "mod_include.c", NULL };
    ap_hook_post_config(ssi_setsplitvars_post_config, prereq, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA ssi_setsplitvars_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                        /* make dir config */
    NULL,                        /* merge dir config --- default is to override */
    NULL,                        /* make server config */
    NULL,                        /* merge server config */
    NULL,                        /* config directives apr_table_t */
    register_hooks               /* register hooks */
};
