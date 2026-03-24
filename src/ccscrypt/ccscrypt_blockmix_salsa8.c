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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccscrypt_internal.h>

void ccscrypt_blockmix_salsa8(uint8_t *B, uint8_t *Y, size_t r)
{
    uint8_t X[64];

    cc_memcpy(X, &B[(2 * r - 1) * 64], 64);

    for (size_t i = 0; i < 2 * r; i++) {
        cc_xor(64, X, X, &B[i * 64]);
        ccscrypt_salsa20_8(X, X);
        cc_memcpy(&Y[i * 64], X, 64);
    }

    for (size_t i = 0; i < r; i++) {
        cc_memcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
    }

    for (size_t i = 0; i < r; i++) {
        cc_memcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
    }
}
