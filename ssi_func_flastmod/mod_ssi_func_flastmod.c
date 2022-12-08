/* 
**  mod_ssi_func_flastmod.c -- Apache ssi_func_flastmod module
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_ssi_func_flastmod.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ssi_func_flastmod in as follows:
**
**    #   httpd.conf
**    LoadModule ssi_func_flastmod_module modules/mod_ssi_func_flastmod.so
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

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include "mod_include.h"
#include "mod_ssi_func.h"

module AP_MODULE_DECLARE_DATA ssi_func_flastmod_module;

static APR_OPTIONAL_FN_TYPE(ssi_func_register) *ssi_func_flastmod_pfn_fr;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *ssi_func_flastmod_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *ssi_func_flastmod_pfn_ps;

/* taken from mod_include.c */
/* ensure that path is relative, and does not contain ".." elements
 * ensentially ensure that it does not match the regex:
 * (^/|(^|/)\.\.(/|$))
 * XXX: Simply replace with apr_filepath_merge                    
 */
static int is_only_below(const char *path)
{
#ifdef HAVE_DRIVE_LETTERS
    if (path[1] == ':') 
        return 0;
#endif
#ifdef NETWARE
    if (ap_strchr_c(path, ':'))
        return 0;
#endif
    if (path[0] == '/') {
        return 0;
    }
    while (*path) {
        int dots = 0;
        while (path[dots] == '.')
            ++dots;
#if defined(WIN32) 
        /* If the name is canonical this is redundant
         * but in security, redundancy is worthwhile.
         * Does OS2 belong here (accepts ... for ..)?
         */
        if (dots > 1 && (!path[dots] || path[dots] == '/'))
            return 0;
#else
        if (dots == 2 && (!path[dots] || path[dots] == '/'))
            return 0;
#endif
        path += dots;
        /* Advance to either the null byte at the end of the
         * string or the character right after the next slash,
         * whichever comes first
         */
        while (*path && (*path++ != '/')) {
            continue;
        }
    }
    return 1;
}

/* taken from mod_include.c */
static int find_file(request_rec *r, const char *directive, const char *tag,
                     char *tag_val, apr_finfo_t *finfo)
{
    char *to_send = tag_val;
    request_rec *rr = NULL;
    int ret=0;
    char *error_fmt = NULL;
    apr_status_t rv = APR_SUCCESS;

    if (!strcmp(tag, "file")) {
        /* XXX: Port to apr_filepath_merge
         * be safe; only files in this directory or below allowed 
         */
        if (!is_only_below(tag_val)) {
            error_fmt = "unable to access file \"%s\" "
                        "in parsed file %s";
        }
        else {
            ap_getparents(tag_val);    /* get rid of any nasties */

            /* note: it is okay to pass NULL for the "next filter" since
               we never attempt to "run" this sub request. */
            rr = ap_sub_req_lookup_file(tag_val, r, NULL);

            if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
                to_send = rr->filename;
                if ((rv = apr_stat(finfo, to_send, 
                    APR_FINFO_GPROT | APR_FINFO_MIN, rr->pool)) != APR_SUCCESS
                    && rv != APR_INCOMPLETE) {
                    error_fmt = "unable to get information about \"%s\" "
                        "in parsed file %s";
                }
            }
            else {
                error_fmt = "unable to lookup information about \"%s\" "
                            "in parsed file %s";
            }
        }

        if (error_fmt) {
            ret = -1;
            ap_log_rerror(APLOG_MARK, APLOG_ERR,
                          rv, r, error_fmt, to_send, r->filename);
        }

        if (rr) ap_destroy_sub_req(rr);
        
        return ret;
    }
    else if (!strcmp(tag, "virtual")) {
        /* note: it is okay to pass NULL for the "next filter" since
           we never attempt to "run" this sub request. */
        rr = ap_sub_req_lookup_uri(tag_val, r, NULL);

        if (rr->status == HTTP_OK && rr->finfo.filetype != 0) {
            memcpy((char *) finfo, (const char *) &rr->finfo,
                   sizeof(rr->finfo));
            ap_destroy_sub_req(rr);
            return 0;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "unable to get information about \"%s\" "
                        "in parsed file %s",
                        tag_val, r->filename);
            ap_destroy_sub_req(rr);
            return -1;
        }
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "unknown parameter \"%s\" to tag %s in %s",
                    tag, directive, r->filename);
        return -1;
    }
}

static char* handle_func_flastmod(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                  request_rec *r, ap_filter_t *f,
                                  apr_bucket *head_ptr,
				  apr_bucket **inserted_head,
                                  char **tag, char **tag_val)
{
    char *t_val = NULL;
    char *parsed_string = NULL;
    apr_finfo_t  finfo;

    while (1) {
        ssi_func_flastmod_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "file") || !(strcmp(*tag, "virtual"))) {
            parsed_string = ssi_func_flastmod_pfn_ps(r, ctx, *tag_val, NULL, 
                                                     MAX_STRING_LEN, 0);
            if (!find_file(r, "flastmod", *tag, parsed_string, &finfo)) {
                t_val = ap_ht_time(r->pool, finfo.mtime, ctx->time_str, 0);
            DEBUG("found flastmod for file = %s", parsed_string);
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for add() in parsed doc %s",
                          *tag, r->filename);
        }
    }

    DEBUG("flastmod(%s) = %s", parsed_string, t_val);
    return apr_pstrdup(r->pool, (t_val != NULL) ? t_val : "(none)");
}

static int ssi_func_flastmod_post_config(apr_pool_t *p, apr_pool_t *plog,
                                     apr_pool_t *ptemp, server_rec *s)
{
    ssi_func_flastmod_pfn_gtv  = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    ssi_func_flastmod_pfn_ps   = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);
    ssi_func_flastmod_pfn_fr   = APR_RETRIEVE_OPTIONAL_FN(ssi_func_register);

    if ((ssi_func_flastmod_pfn_gtv) && (ssi_func_flastmod_pfn_ps) &&
        (ssi_func_flastmod_pfn_fr)) {
        ssi_func_flastmod_pfn_fr("flastmod", handle_func_flastmod);
        DEBUG("ssi flastmod registered");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ssi flastmod registered failed");
    }

    srand(time(NULL));

    return OK;
}

static void ssi_func_flastmod_register_hooks(apr_pool_t *p)
{
    static const char * const prereq[] = { "mod_ssi_func.c", NULL };
    ap_hook_post_config(ssi_func_flastmod_post_config, prereq, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ssi_func_flastmod_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                        /* create per-dir    config structures */
    NULL,                        /* merge  per-dir    config structures */
    NULL,                        /* create per-server config structures */
    NULL,                        /* merge  per-server config structures */
    NULL,                        /* table of config file commands       */
    ssi_func_flastmod_register_hooks  /* register hooks                      */
};
