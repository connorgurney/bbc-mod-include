/* 
**  mod_ssi_func_math.c -- Apache ssi_func_math module
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_ssi_func_math.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ssi_func_math in as follows:
**
**    #   httpd.conf
**    LoadModule ssi_func_math_module modules/mod_ssi_func_math.so
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
#include "ap_config.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include "mod_include.h"
#include "mod_ssi_func.h"

module AP_MODULE_DECLARE_DATA ssi_func_math_module;

static APR_OPTIONAL_FN_TYPE(ssi_func_register) *ssi_func_math_pfn_fr;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *ssi_func_math_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *ssi_func_math_pfn_ps;

static char* handle_func_add(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int sum = 0;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "value")) {
            sum += atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found math add with sum = %d", sum);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for add() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    DEBUG("math sum = %d", sum);
    return apr_psprintf(r->pool, "%d", sum);
}

static char* handle_func_mult(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int res = 0;
    int init = 0;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "value")) {
            if (!init) {
                res = atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                MAX_STRING_LEN, 0));
                init = 1;
            }
            else {
                res *= atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                 MAX_STRING_LEN, 0));
            }
            DEBUG("found math mult with res = %d", res);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for mult() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    DEBUG("math mult = %d", res);
    return apr_psprintf(r->pool, "%d", res);
}

static char* handle_func_div(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int res = 0;
    int init = 0;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "value")) {
            if (!init) {
                res = atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                MAX_STRING_LEN, 0));
                init = 1;
            }
            else {
                res /= atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                 MAX_STRING_LEN, 0));
            }
            DEBUG("found math div with res = %d", res);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for div() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    DEBUG("math div = %d", res);
    return apr_psprintf(r->pool, "%d", res);
}

static char* handle_func_mod(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int res = 0;
    int init = 0;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "value")) {
            if (!init) {
                res = atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                MAX_STRING_LEN, 0));
                init = 1;
                DEBUG("found math mod with initial res = %d", res);
            }
            else {
                res %= atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                                 MAX_STRING_LEN, 0));
                DEBUG("found math mod with res = %d", res);
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for mod() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    DEBUG("math mod = %d", res);
    return apr_psprintf(r->pool, "%d", res);
}

static char* handle_func_neg(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int val = 0;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "value")) {
            val += atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found math neg with val = %d", val);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for neg() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    val = 0 - val;
    DEBUG("neg = %d", val);
    return apr_psprintf(r->pool, "%d", val);
}

static char* handle_func_cmp(include_ctx_t *ctx, apr_bucket_brigade **bb,
                             request_rec *r, ap_filter_t *f,
                             apr_bucket *head_ptr,
                             apr_bucket **inserted_head,
                             char **tag, char **tag_val)
{
    char *op = NULL;
    int a;
    int b;
    int result;

    while (1) {
        ssi_func_math_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "a")) {
            a = atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found math cmp a = %d", a);
        }
        else if (!strcmp(*tag, "b")) {
            b = atoi(ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found math cmp b = %d", b);
        }
        else if (!strcmp(*tag, "op")) {
            op = ssi_func_math_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0);
            DEBUG("found math cmp op = %s", op);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for cmp() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    if (op == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "ssi math cmp operation missing in parsed doc %s",
                      *tag, r->filename);
        return NULL;
    }

    if (!strcmp("lt", op)) {
        result = (a < b);
    }
    else if (!strcmp("le", op)) {
        result = (a <= b);
    }
    else if (!strcmp("gt", op)) {
        result = (a > b);
    }
    else if (!strcmp("ge", op)) {
        result = (a >= b);
    }
    else if (!strcmp("eq", op)) {
        result = (a == b);
    }
    else if (!strcmp("ne", op)) {
        result = (a != b);
    }

    DEBUG("math cmp = %d", result);
    return apr_psprintf(r->pool, "%d", result);
}

static int ssi_func_math_post_config(apr_pool_t *p, apr_pool_t *plog,
                                     apr_pool_t *ptemp, server_rec *s)
{
    ssi_func_math_pfn_gtv  = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    ssi_func_math_pfn_ps   = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);
    ssi_func_math_pfn_fr   = APR_RETRIEVE_OPTIONAL_FN(ssi_func_register);

    if ((ssi_func_math_pfn_gtv) && (ssi_func_math_pfn_ps) &&
        (ssi_func_math_pfn_fr)) {
        ssi_func_math_pfn_fr("add", handle_func_add);
        ssi_func_math_pfn_fr("mult", handle_func_mult);
        ssi_func_math_pfn_fr("div", handle_func_div);
        ssi_func_math_pfn_fr("mod", handle_func_mod);
        ssi_func_math_pfn_fr("cmp", handle_func_cmp);
        ssi_func_math_pfn_fr("neg", handle_func_neg);
        DEBUG("ssi add,mult,div,mod,cmp,neg registered");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                     "ssi add,mult,div,mod,cmp,neg registered failed");
    }

    srand(time(NULL));

    return OK;
}

static void ssi_func_math_register_hooks(apr_pool_t *p)
{
    static const char * const prereq[] = { "mod_ssi_func.c", NULL };
    ap_hook_post_config(ssi_func_math_post_config, prereq, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ssi_func_math_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                        /* create per-dir    config structures */
    NULL,                        /* merge  per-dir    config structures */
    NULL,                        /* create per-server config structures */
    NULL,                        /* merge  per-server config structures */
    NULL,                        /* table of config file commands       */
    ssi_func_math_register_hooks  /* register hooks                      */
};
