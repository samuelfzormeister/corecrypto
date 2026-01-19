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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccdrbg_impl.h>

#define CCDRBG_CTR_MAX_KEYLEN   CCAES_KEY_SIZE_256
#define CCDRBG_CTR_BLOCK_LENGTH CCAES_BLOCK_SIZE

struct ccdrbg_nistctr_state {
    uint8_t V[CCDRBG_CTR_BLOCK_LENGTH];
    uint8_t Key[CCDRBG_CTR_MAX_KEYLEN];
    uint64_t reseed_counter;
    const struct ccdrbg_nistctr_custom *custom;
};

/*
 * NIST CTR based DRBGs can use the following ciphers:
 * - 3 Key TDEA
 * - AES with key sizes of 128, 192 or 256.
 */

/* SP800-90A, 9.4, Removing a DRBG Instantiation */
static void
done(struct ccdrbg_state *ctx)
{
    cc_clear(sizeof(struct ccdrbg_nistctr_state), ctx);
}

/*
int (*init)(const struct ccdrbg_info *info, struct ccdrbg_state *drbg,
            size_t entropyLength, const void* entropy,
            size_t nonceLength, const void* nonce,
            size_t psLength, const void* ps);
 */

static int init(const struct ccdrbg_info *info, struct ccdrbg_state *drbg,
                size_t entropy_len, const void *entropy,
                size_t nonce_len, const void *nonce,
                size_t ps_len, const void *ps)
{

    /* */
    return CCDRBG_STATUS_OK;
}

void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom)
{
    cc_abort("incomplete NIST CTR based DRBG - aborting in the event that it is ever called\n");
    info->size = sizeof(struct ccdrbg_nistctr_state) + sizeof(struct ccdrbg_nistctr_custom);

    info->done = done;
}
