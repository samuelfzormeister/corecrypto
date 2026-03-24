/*
 * Copyright (C) 2026 The PureDarwin Project, All rights reserved.
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

#ifndef _CORECRYPTO_CCKEM_H_
#define _CORECRYPTO_CCKEM_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>

struct cckem_info;

// --- Security makes reference to an 'info' field. --- //
struct cckem_pub_ctx {
    struct cckem_info *info;

    cc_unit u[];
};

struct cckem_full_ctx {
    struct cckem_info *info;

    cc_unit u[];
};

typedef struct cckem_pub_ctx *cckem_pub_ctx_t;
typedef struct cckem_full_ctx *cckem_full_ctx_t;

// cckem_sizeof_full_ctx(info)
// cckem_sizeof_oub_ctx(info)

// cckem_pub_ctx_clear(info, ctx)
// cckem_full_ctx_clear(info, ctx)

size_t cckem_pubkey_nbytes_ctx(cckem_pub_ctx_t);
size_t cckem_privkey_nbytes_ctx(cckem_pub_ctx_t);

size_t cckem_encapsulated_key_nbytes_info(const struct cckem_info *info);

int cckem_import_pubkey(const struct cckem_info *info, size_t pubkey_len, const void *pubkey, cckem_pub_ctx_t key);
int cckem_import_privkey(const struct cckem_info *info, size_t privkey_len, const void *privkey, cckem_full_ctx_t key);

int cckem_export_pubkey(cckem_pub_ctx_t key, size_t *pk_len, void *pubkey);

int cckem_export_privkey(cckem_full_ctx_t key, size_t *pk_len, void *privkey);

int cckem_encapsulate(cckem_pub_ctx_t pub, size_t ek_len, void *ek, size_t sk_len, void *sk, struct ccrng_state *rng);

int cckem_decapsulate(cckem_full_ctx_t pub, size_t ek_len, const void *ek, size_t sk_len, void *sk);

#endif /* _CORECRYPTO_CCKEM_H_ */
