/*
 * Copyright (C) 2025 The PureDarwin Project, All rights reserved.
 *
 * @LICENSE_HEADER_BEGIN@
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @LICENSE_HEADER_END@
 */

#ifndef _CORECRYPTO_CCDH_H_
#define _CORECRYPTO_CCDH_H_

#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>

// Something about 'sructures such as ccdh_gp_decl_n' has me a bit curious as to whether the GPs are actually just CCZPs
// That and the whole layout looks extremely similar.
struct ccdh_gp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(16);

typedef struct ccdh_gp *ccdh_gp_t;
typedef const struct ccdh_gp *ccdh_const_gp_t;

/* either this or it's a macro. take your pick. */
CC_INLINE
cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return gp->n;
}

/* Prime is located at 0. */
CC_INLINE
const cc_unit *ccdh_gp_prime(ccdh_const_gp_t gp) {
    return &gp->ccn[0];
};

cc_unit *ccdh_gp_g(ccdh_const_gp_t gp);
cc_unit ccdh_gp_l(ccdh_const_gp_t); /* the L field is a signular unit at the end of the GP */
cc_unit *ccdh_gp_order(ccdh_const_gp_t);
cc_size ccdh_gp_order_bitlen(ccdh_const_gp_t);
cc_size ccdh_gp_size(cc_size);

/*
 * todo:
 *  - ccdh_gp_g
 *  - ccdh_gp_l
 *  - ccdh_gp_prime
 *  - ccdh_gp_order
 *  - ccdh_gp_order_bitlen
 *  - ccdh_gp_size
 *
 *  newer corecrypto has everything as a function now, makes my job easier :)
 */

int ccdh_init_gp(ccdh_gp_t gp, cc_size n, cc_unit *p, cc_unit *g, cc_size l);

struct ccdh_pub_ctx {
    ccdh_const_gp_t gp;
};

typedef struct ccdh_pub_ctx *ccdh_pub_ctx_t;

struct ccdh_full_ctx {
    ccdh_const_gp_t gp;
};

typedef struct ccdh_full_ctx *ccdh_full_ctx_t;

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng, ccdh_full_ctx_t ctx);

int ccdh_import_pub(ccdh_const_gp_t gp, size_t pub_key_len, const void *pub_key, ccdh_pub_ctx_t pub);
void ccdh_export_pub(ccdh_pub_ctx_t ctx, void *out);

int ccdh_compute_shared_secret(ccdh_full_ctx_t ctx, ccdh_pub_ctx_t pub, size_t *shared_key_len, void *shared_key, struct ccrng_state *rng);

size_t ccdh_export_pub_size(ccdh_pub_ctx_t ctx);

#endif /* _CORECRYPTO_CCDH_H_ */
