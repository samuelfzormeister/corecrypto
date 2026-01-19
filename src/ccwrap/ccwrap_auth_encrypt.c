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

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccwrap.h>
#include <corecrypto/ccwrap_priv.h>

int ccwrap_auth_encrypt_withiv(struct ccmode_ecb *mode, ccecb_ctx *context, size_t length, const uint8_t *key, size_t *wrapped_length, uint8_t *wrapped_key, const uint8_t *iv)
{
    uint64_t R[3]; // + 1 for the outgoing IV.
    uint64_t B;
    size_t n = (length / CCWRAP_SEMIBLOCK);

    if (length != CCAES_KEY_SIZE_128) {
        return CCERR_PARAMETER;
    }

    uint64_t A = *(uint64_t *)iv;
    R[0] = A;
    for (int i = 1; i < n; i++) {
        R[i] = key[i];
    }

    for (int j = 0; j < 5; j++) {
        for (int k = 1; k < n; k++) {
            uint64_t tmp = A | R[k];
            if (mode->ecb(context, 1, &tmp, &B) == CCERR_OK) {
                A = CC_H2BE64(B) ^ (n * j) + k;
                R[k] = CC_H2LE64(B);
            } else {
                CC_MEMSET(R, 0, sizeof(R));
                return CCERR_INTERNAL;
            }
        }
    }

    *wrapped_length = ccwrap_wrapped_size(length);
    CC_MEMCPY(wrapped_key, R, ccwrap_wrapped_size(length));

    return CCERR_OK;
}

int ccwrap_auth_encrypt(struct ccmode_ecb *mode, ccecb_ctx *context, size_t key_length, const uint8_t *key, size_t *wrapped_key_length, uint8_t *wrapped_key)
{
    uint8_t iv[CCAES_BLOCK_SIZE] = CCWRAP_DEFAULT_IV;
    
    return ccwrap_auth_encrypt_withiv(mode, context, key_length, key, wrapped_key_length, wrapped_key, iv);
}
