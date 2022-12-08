/* 
**  mod_ssi_func.c -- Apache SSI function tag module
**
**  To play with this module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_ssi_func.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ssi_func_math in as follows:
**
**    #   httpd.conf
**    LoadModule ssi_func_module modules/mod_ssi_func.so
** 
**  This will not do anything unless use use modules using the
**  the available #func SSI tag.
**
**  Written by Andre Breiler <andre.breiler@is.bbc.co.uk> 2004
**    with referneces to mod_include
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

#include "mod_ssi_func.h"

module AP_MODULE_DECLARE_DATA ssi_func_module;

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) *ssi_func_pfn_rih;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *ssi_func_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *ssi_func_pfn_ps;

static apr_hash_t *ssi_func_hash;

static int handle_func(include_ctx_t *ctx, apr_bucket_brigade **bb, 
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head)
{
    char *tag     = NULL;
    char *tag_val = NULL;
    char *var     = NULL;
    char *func    = NULL;
    apr_bucket *tmp_buck;
    char *ps;
    request_rec *sub = r->main;
    apr_pool_t *p = r->pool;
    char* (*handle_func)(include_ctx_t *, apr_bucket_brigade **,
                         request_rec *, ap_filter_t *, apr_bucket *,
                         apr_bucket **, char **, char **);
    char* rv;

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
            ssi_func_pfn_gtv(ctx, &tag, &tag_val, 1);
            /* FIXME what is 0 and 1 doing as it looks the same */
            if (tag_val == NULL) {
                return (tag == NULL) ? 0 : 1;
            }
            else if (!strcmp(tag, "var")) {
                var = ssi_func_pfn_ps(r, ctx, tag_val, NULL,
                                          MAX_STRING_LEN, 0);
            }
            else if (!strcmp(tag, "func")) {
                if (var == (char *) NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                           "variable must precede func in func directive in %s",
                           r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, 
                                        *inserted_head);
                    return (-1);
                }
                ps = ssi_func_pfn_ps(r, ctx, tag_val, NULL, 
                                         MAX_STRING_LEN, 0);
              handle_func = (ssi_func_handler_fn_t *)apr_hash_get(ssi_func_hash,
                                                       ps, 
                                                       APR_HASH_KEY_STRING);
                if (handle_func != NULL) {
                    rv = (*handle_func)(ctx, bb, r, f, head_ptr,
                                        inserted_head, &tag, &tag_val);
                    if (rv == NULL) {
                        return (-1);
                    } else {
                        apr_table_setn(r->subprocess_env, apr_pstrdup(p, var),
                                       apr_pstrdup(p, rv));
                        return 0;
                    }
                } else {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                  "unknown ssi func \"%s\" in parsed doc %s",
                                  ps, r->filename);
                    CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                    return -1;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                             "Invalid tag for ssi func directive in %s",
                             r->filename);
                CREATE_ERROR_BUCKET(ctx, tmp_buck, head_ptr, *inserted_head);
                return -1;
            }
        }
    }
    return 0;
}

static void ssi_func_register(char *funcname, ssi_func_handler_fn_t *func)
{
    apr_hash_set(ssi_func_hash, funcname, APR_HASH_KEY_STRING,
                 (const void *)func);
    DEBUG("ssi_func_register called with %s", funcname);
}

static int ssi_func_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    ssi_func_hash = apr_hash_make(p);
    
    ssi_func_pfn_rih = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    ssi_func_pfn_gtv = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    ssi_func_pfn_ps  = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);

    if ((ssi_func_pfn_rih) && (ssi_func_pfn_gtv) && (ssi_func_pfn_ps)) {
        ssi_func_pfn_rih("func", handle_func);
    DEBUG("\"func\" registered as ssi tag");
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "\"func\" failed to register as ssi tag");
    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const prereq[] = { "mod_include.c", NULL };
    ap_hook_post_config(ssi_func_post_config, prereq, NULL, APR_HOOK_FIRST);

    APR_REGISTER_OPTIONAL_FN(ssi_func_register);
}

module AP_MODULE_DECLARE_DATA ssi_func_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                        /* make dir config */
    NULL,                        /* merge dir config --- default is to override */
    NULL,                        /* make server config */
    NULL,                        /* merge server config */
    NULL,                        /* config directives apr_table_t */
    register_hooks               /* register hooks */
};
