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

struct ccaes_intel_xts_encrypt_ctx {
    vng_aes_intel_encrypt_ctx encrypt[1];
    vng_aes_intel_encrypt_ctx encrypt_tweak[1];
};

// forward declaration
static void key_sched_wrapper_aesni(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key);

static int init_wrapper_aesni(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key)
{
    key_sched_wrapper_aesni(xts, ctx, key_size, data_key, tweak_key);
    return CCERR_OK;
}

static void key_sched_wrapper_aesni(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;

    vng_aes_encrypt_aesni_key(data_key, key_size, key->encrypt);
    vng_aes_encrypt_aesni_key(tweak_key, key_size, key->encrypt_tweak);
}

static int set_tweak_wrapper_aesni(const ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;

    vng_aes_encrypt_aesni(iv, (uint8_t *)tweak, key->encrypt_tweak);

    return CCERR_OK;
}

static void *xts_wrapper_aesni(const ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks, const void *in, void *out)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;
    uint8_t *T = (uint8_t *)tweak;

    if (vng_aes_xts_encrypt_aesni(in, nblocks * CCAES_BLOCK_SIZE, out, T, key->encrypt)) {
        return NULL;
    } else {
        return T;
    }
}

const struct ccmode_xts ccaes_intel_xts_encrypt_aesni_mode = {
    /* constants */
    .size = sizeof(struct ccaes_intel_xts_encrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .tweak_size = 16,

    /* functions */
    .init = init_wrapper_aesni,
    .key_sched = key_sched_wrapper_aesni,
    .set_tweak = set_tweak_wrapper_aesni,
    .xts = xts_wrapper_aesni,

    .custom = NULL,
    .custom1 = NULL,
};

// forward declaration
static void key_sched_wrapper_opt(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key);

static int init_wrapper_opt(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key)
{
    key_sched_wrapper_opt(xts, ctx, key_size, data_key, tweak_key);
    return CCERR_OK;
}

static void key_sched_wrapper_opt(const struct ccmode_xts *xts, ccxts_ctx *ctx, size_t key_size, const void *data_key, const void *tweak_key)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;

    vng_aes_encrypt_opt_key(data_key, key_size, key->encrypt);
    vng_aes_encrypt_opt_key(tweak_key, key_size, key->encrypt_tweak);
}

static int set_tweak_wrapper_opt(const ccxts_ctx *ctx, ccxts_tweak *tweak, const void *iv)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;

    vng_aes_encrypt_opt(iv, (uint8_t *)tweak, key->encrypt_tweak);

    return CCERR_OK;
}

static void *xts_wrapper_opt(const ccxts_ctx *ctx, ccxts_tweak *tweak, size_t nblocks, const void *in, void *out)
{
    struct ccaes_intel_xts_encrypt_ctx *key = (struct ccaes_intel_xts_encrypt_ctx *)ctx;
    uint8_t *T = (uint8_t *)tweak;

    if (vng_aes_xts_encrypt_opt(in, nblocks * CCAES_BLOCK_SIZE, out, T, key->encrypt)) {
        return NULL;
    } else {
        return T;
    }
}

const struct ccmode_xts ccaes_intel_xts_encrypt_opt_mode = {
    /* constants */
    .size = sizeof(struct ccaes_intel_xts_encrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .tweak_size = 16,

    /* functions */
    .init = init_wrapper_opt,
    .key_sched = key_sched_wrapper_opt,
    .set_tweak = set_tweak_wrapper_opt,
    .xts = xts_wrapper_opt,

    .custom = NULL,
    .custom1 = NULL,
};

#endif
