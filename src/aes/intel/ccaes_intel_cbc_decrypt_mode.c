/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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

static int init_wrapper_opt(const struct ccmode_cbc *ecb, cccbc_ctx *ctx, size_t key_len, const void *key)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_opt_key(key, key_len, k->ctx);
    return 0;
}

static int cbc_wrapper_opt(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    size_t finalBlockOffset = (nblocks-1) * CCAES_BLOCK_SIZE;
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_opt_cbc(in, (unsigned char *)iv, nblocks, out, k->ctx);
    
    //
    // funny story: We're SUPPOSED to update the IV. Which, the VNG ASM doesn't.
    //
    cc_memcpy(iv, out+finalBlockOffset, CCAES_BLOCK_SIZE);

    return 0;
}

const struct ccmode_cbc ccaes_intel_cbc_decrypt_opt_mode = {
    .size = sizeof(ccaes_intel_decrypt_key),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_opt,
    .cbc = cbc_wrapper_opt,
    .custom = NULL,
};

static int init_wrapper_aesni(const struct ccmode_cbc *ecb, cccbc_ctx *ctx, size_t key_len, const void *key)
{
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_aesni_key(key, key_len, k->ctx);
    return 0;
}

static int cbc_wrapper_aesni(const cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    size_t finalBlockOffset = (nblocks-1) * CCAES_BLOCK_SIZE;
    struct ccaes_intel_decrypt_key *k = (struct ccaes_intel_decrypt_key *)ctx;
    vng_aes_decrypt_aesni_cbc(in, (unsigned char *)iv, nblocks, out, k->ctx);
    
    //
    // funny story: We're SUPPOSED to update the IV. Which, the VNG ASM doesn't.
    //
    cc_memcpy(iv, out+finalBlockOffset, CCAES_BLOCK_SIZE);
    return 0;
}

const struct ccmode_cbc ccaes_intel_cbc_decrypt_aesni_mode = {
    .size = sizeof(ccaes_intel_decrypt_key),
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_aesni,
    .cbc = cbc_wrapper_aesni,
    .custom = NULL,
};

#endif
