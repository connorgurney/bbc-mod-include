/* 
**  mod_ssi_func_rnd.c -- Apache ssi_func_rnd module
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_ssi_func_rnd.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ssi_func_rnd in as follows:
**
**    #   httpd.conf
**    LoadModule ssi_func_rnd_module modules/mod_ssi_func_rnd.so
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

module AP_MODULE_DECLARE_DATA ssi_func_rnd_module;

static APR_OPTIONAL_FN_TYPE(ssi_func_register) *ssi_func_rnd_pfn_fr;
static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *ssi_func_rnd_pfn_gtv;
static APR_OPTIONAL_FN_TYPE(ap_ssi_parse_string) *ssi_func_rnd_pfn_ps;

static char* handle_func_random(include_ctx_t *ctx, apr_bucket_brigade **bb,
                                request_rec *r, ap_filter_t *f,
                                apr_bucket *head_ptr,
				apr_bucket **inserted_head,
                                char **tag, char **tag_val)
{
    int min = 0, max = 0, random = 0, itemcnt = 0;
    char *srandom = NULL;
    apr_array_header_t *list = apr_array_make(r->pool, 10, sizeof(char *));

    while (1) {
        ssi_func_rnd_pfn_gtv(ctx, tag, tag_val, 1);
        if (*tag_val == NULL) {
            break;
        }
        else if (!strcmp(*tag, "min")) {
            min = atoi(ssi_func_rnd_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found random min = %d", min);
        }
        else if (!strcmp(*tag, "max")) {
            max = atoi(ssi_func_rnd_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0));
            DEBUG("found random max = %d", max);
        }
        else if (!strcmp(*tag, "item")) {
            char ** pos = (char **)apr_array_push(list);
            *pos = ssi_func_rnd_pfn_ps(r, ctx, *tag_val, NULL,
                                       MAX_STRING_LEN, 0);
            itemcnt++;
            DEBUG("added random item = %s", *pos);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "unknown tag \"%s\" for random() in parsed doc %s",
                          *tag, r->filename);
            return NULL;
        }
    }

    /* be nice and switch the range if wrong way around */
    if (max < min) {
        int t = min;
        min = max;
        max = t;
    }
    else if (min == max && itemcnt) {
        min = 0;
        max = itemcnt - 1;
    }

    if ((max - min) >= 0) {
                random = rand() % (max - min + 1) + min;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "range invalid for random() in parsed doc %s",
                      tag, r->filename);
    }
    if ((random - min) >= 0 && (random - min) < list->nelts) {
        srandom = apr_pstrdup(r->pool, ((char **)list->elts)[random - min]);
    }
    else {
        srandom = apr_psprintf(r->pool, "%d", random);
    }
    DEBUG("random = %s (%d)", srandom, random);
    return srandom;
}

static int ssi_func_rnd_post_config(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *s)
{
    ssi_func_rnd_pfn_gtv  = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);
    ssi_func_rnd_pfn_ps   = APR_RETRIEVE_OPTIONAL_FN(ap_ssi_parse_string);
    ssi_func_rnd_pfn_fr   = APR_RETRIEVE_OPTIONAL_FN(ssi_func_register);

    if ((ssi_func_rnd_pfn_gtv) && (ssi_func_rnd_pfn_ps) &&
        (ssi_func_rnd_pfn_fr)) {
        ssi_func_rnd_pfn_fr("random", handle_func_random);
        DEBUG("random registered");
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "random registered failed");
    }

    srand(time(NULL));

    return OK;
}

static void ssi_func_rnd_register_hooks(apr_pool_t *p)
{
    static const char * const prereq[] = { "mod_ssi_func.c", NULL };
    ap_hook_post_config(ssi_func_rnd_post_config, prereq, NULL, APR_HOOK_FIRST);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ssi_func_rnd_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                        /* create per-dir    config structures */
    NULL,                        /* merge  per-dir    config structures */
    NULL,                        /* create per-server config structures */
    NULL,                        /* merge  per-server config structures */
    NULL,                        /* table of config file commands       */
    ssi_func_rnd_register_hooks  /* register hooks                      */
};
