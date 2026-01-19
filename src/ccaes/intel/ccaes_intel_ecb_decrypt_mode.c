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

#include <corecrypto/ccaes.h>

#if CCAES_INTEL_ASM

#include "vng_aes_intel.h"

struct ccaes_intel_decrypt_key {
    vng_aes_intel_decrypt_ctx ctx[1];
} typedef ccaes_intel_decrypt_key;

static int init_wrapper_opt(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_len, const void *key)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_opt_key(key, key_len, k->ctx);
    return 0;
}

static int ecb_wrapper_opt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;

    while (nblocks--) {
        vng_aes_decrypt_opt(in, out, k->ctx);
        in += CCAES_BLOCK_SIZE;
        out += CCAES_BLOCK_SIZE;
    }

    return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_decrypt_opt_mode = {
    .size = sizeof(ccaes_intel_decrypt_key),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_opt,
    .ecb = ecb_wrapper_opt,
};

static int init_wrapper_aesni(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_len, const void *key)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_aesni_key(key, key_len, k->ctx);
    return 0;
}

static int ecb_wrapper_aesni(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;

    while (nblocks--) {
        vng_aes_decrypt_aesni(in, out, k->ctx);
        in += CCAES_BLOCK_SIZE;
        out += CCAES_BLOCK_SIZE;
    }

    return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_decrypt_aesni_mode = {
    .size = sizeof(ccaes_intel_decrypt_key),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_aesni,
    .ecb = ecb_wrapper_aesni,
};

#endif
