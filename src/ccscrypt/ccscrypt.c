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

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccscrypt_internal.h>
#include <corecrypto/ccsha2.h>

int ccscrypt(size_t password_len, const void *password, 
             size_t salt_len, const void *salt, 
             void *storage, 
             uint64_t N, uint32_t r, uint32_t p, 
             size_t dk_len, void *dk)
{
    int64_t size = ccscrypt_storage_size(N, r, p);

    if (size < 0) {
        return (int)size;
    }

    size_t B_size = (128 * r * p);
    size_t XY_size = (128 * r);

    uint8_t *B = storage;
    uint8_t *X = &((uint8_t *)storage)[B_size];
    uint8_t *Y = &((uint8_t *)storage)[B_size + XY_size];
    uint8_t *T = &((uint8_t *)storage)[B_size + XY_size + XY_size];

    int ret = ccpbkdf2_hmac(ccsha256_di(), password_len, password, salt_len, salt, 1, B_size, B);
    cc_require_action(ret == 0, out, ret = CCERR_INTERNAL);

    for (size_t i = 0; i < p; i++) {
        ccscrypt_romix(r, &B[i * 128 * r], N, T, X, Y);
    }

    ret = ccpbkdf2_hmac(ccsha256_di(), password_len, password, B_size, B, 1, dk_len, dk);
    cc_require_action(ret == 0, out, ret = CCERR_INTERNAL);

    ret = CCERR_OK;

out:
    cc_clear(size, storage);
    return ret;
}

