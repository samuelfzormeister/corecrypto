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

#ifndef _CORECRYPTO_CCEC_H_
#define _CORECRYPTO_CCEC_H_

#include <stdbool.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>

/* SAMUEL ZORMEISTER: this header is a shitshow. i need to clean it up. */

// hunch based on the ccdh stuff
struct ccec_cp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(16);

typedef struct ccec_cp *ccec_cp_t;
typedef const struct ccec_cp *ccec_const_cp_t;

struct ccec_pub_ctx {
};

typedef struct ccec_pub_ctx *ccec_pub_ctx_t;

struct ccec_full_ctx {};

typedef struct ccec_pub_ctx *ccec_full_ctx_t;

#define ccec_pub_ctx_size(_size_) 0
#define ccec_full_ctx_size(_size_) 0

ccec_const_cp_t ccec_get_cp(size_t nbits);

bool ccec_keysize_is_supported(size_t nbits);

int ccec_sign(ccec_full_ctx_t key, size_t len, const void *data, size_t *signature_len, void *signature);

ccec_const_cp_t ccec_get_cp(size_t nbits);

int ccec_verify(ccec_pub_ctx_t key, size_t len, const void *data, size_t signature_len, const void *signature, uint32_t *valid);

size_t ccec_ccn_size(ccec_const_cp_t cp);

int ccec_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t key);

int ccec_get_pubkey_components(ccec_pub_ctx_t key, size_t *key_len,
                               uint8_t *qx, size_t *qx_len,
                               uint8_t *qy, size_t *qy_len);

int ccec_get_fullkey_components(ccec_pub_ctx_t key, size_t *key_len,
                                uint8_t *qx, size_t *qx_len,
                                uint8_t *qy, size_t *qy_len,
                                uint8_t *d, size_t *d_len);

int ccec_make_pub(size_t bits, uint8_t *qx, size_t qx_len, uint8_t *qy, size_t qy_len);

size_t ccec_x963_import_priv_size(size_t key_len);
size_t ccec_x963_import_pub_size(size_t key_len);

int ccec_x963_import_pub(ccec_const_cp_t cp, size_t key_len, uint8_t *key, ccec_pub_ctx_t ctx);
int ccec_x963_import_priv(ccec_const_cp_t cp, size_t key_len, uint8_t *key, ccec_full_ctx_t ctx);

size_t ccec_compact_import_priv_size(size_t key_len);
size_t ccec_compact_import_pub_size(size_t key_len);

int ccec_validate_pub(ccec_pub_ctx_t ctx);

#endif /* _CORECRYPTO_CCEC_H_ */
