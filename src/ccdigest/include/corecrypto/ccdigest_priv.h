/*
 *  ccdigest_priv.h
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2011,2012,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCDIGEST_PRIV_H_
#define _CORECRYPTO_CCDIGEST_PRIV_H_

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccasn1.h>

CC_INLINE CC_NONNULL((1))
bool ccdigest_oid_equal(const struct ccdigest_info *di, ccoid_t oid) {
    if(di->oid == NULL && CCOID(oid) == NULL) return true;
    if(di->oid == NULL || CCOID(oid) == NULL) return false;
    return ccoid_equal(di->oid, oid);
}

typedef const struct ccdigest_info *(ccdigest_lookup)(ccoid_t oid);

#include <stdarg.h>
const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...);

#define ccdigest_copy_state(_di_, _dst_, _src_) cc_memcpy_nochk(_dst_, _src_, (_di_)->state_size)

// --- The functions below act MD-like in their padding scheme. This works for SHA-1, SHA-2, MD4 and MD5. --- //
void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest);
void ccdigest_final_64be(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest);

// --- This is the same as CCSHA512_OUTPUT_SIZE. Update when a larger output digest is added. --- //
#define CCDIGEST_MAX_OUTPUT_SIZE 64

#endif /* _CORECRYPTO_CCDIGEST_PRIV_H_ */
