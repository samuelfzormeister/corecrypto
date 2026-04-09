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

#include <corecrypto/cc_memory.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccwrap.h>
#include <corecrypto/ccwrap_priv.h>

// --- uint64_t array of R --- //
#define CCWRAP_WORKSPACE_R_N(kl) ccn_nof_size(kl / CCWRAP_SEMIBLOCK) + ccn_nof_size(sizeof(uint64_t))

int ccwrap_auth_encrypt_withiv(struct ccmode_ecb *ecb, ccecb_ctx *ecb_key, size_t length, const uint8_t *key, size_t *wrapped_length, uint8_t *wrapped_key, const uint8_t *iv)
{
    CC_WORKSPACE_STACK_DECL(R_ws, CCWRAP_WORKSPACE_R_N(length));
    uint64_t *R = (uint64_t *)R_ws->start;
    uint64_t A, B;
    size_t n = (length / CCWRAP_SEMIBLOCK);
    size_t wrapsize = ccwrap_wrapped_size(length);

    if (ccwrap_argsvalid(ecb, length, wrapsize) == CCERR_PARAMETER) {
        return CCERR_PARAMETER;
    }

    cc_memcpy(&A, iv, sizeof(uint64_t));
    R[0] = A;
    cc_memcpy(&R[1], key, length);

    for (int j = 0; j < 5; j++) {
        for (int i = 1; i <= n; i++) {
            uint64_t tmp = A | R[i];
            if (ccecb_update(ecb, ecb_key, 1, &tmp, &B) == CCERR_OK) {
                // --- TODO: figure out if this works. --- //
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                A = CC_BSWAP64(B) ^ ((n * j) + i);
                R[i] = B;
#else
                A = B ^ ((n * j) + i);
                R[i] = CC_BSWAP64(B);
#endif
            } else {
                CC_WORKSPACE_STACK_FREE_N(R_ws, CCWRAP_WORKSPACE_R_N(length));
                return CCERR_INTERNAL;
            }
        }
    }

    *wrapped_length = wrapsize;
    CC_MEMCPY(wrapped_key, R, wrapsize);

    return CCERR_OK;
}

int ccwrap_auth_encrypt(struct ccmode_ecb *mode, ccecb_ctx *context, size_t key_length, const uint8_t *key, size_t *wrapped_key_length, uint8_t *wrapped_key)
{
    uint8_t iv[CCAES_BLOCK_SIZE] = CCWRAP_DEFAULT_IV;
    
    return ccwrap_auth_encrypt_withiv(mode, context, key_length, key, wrapped_key_length, wrapped_key, iv);
}
