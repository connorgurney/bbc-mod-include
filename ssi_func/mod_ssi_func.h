#ifndef _MOD_SSI_FUNC_H
#define _MOD_SSI_FUNC_H 1

#include "mod_include.h"

/* FIXME: should explain what all this is
 * @param ctx mod_ssi ctx structure
 * @param bb  bucket brigade (not needed in most cases)
 * @param r   structure for current request
 * @param f   apache filter structure
 * @param head_ptr bucket brigade head pointer (needed to insert error buckets)
 * @param inserted_head bucket pointer (needed for error bucket only)
 * @param tag pointer to current tag
 * @param val pointer to current value
 */
typedef char* (ssi_func_handler_fn_t)(include_ctx_t *ctx, apr_bucket_brigade **bb,
                       request_rec *r, ap_filter_t *f, apr_bucket *head_ptr, 
                       apr_bucket **inserted_head, char **tag, char **val);

/**
 * registerable function names
 * @param funcname The name of the function
 * @param func The function which handles it
 */
APR_DECLARE_OPTIONAL_FN(void, ssi_func_register, 
                        (char *funcname, ssi_func_handler_fn_t *func));

#endif /* _MOD_SSI_FUNC_H */
