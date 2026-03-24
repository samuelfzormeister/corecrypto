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

void ccscrypt_romix(size_t r, uint8_t *B, uint64_t N, uint8_t *T, uint8_t *X, uint8_t *Y)
{
    uint64_t i;
    uint64_t j;

    cc_memcpy(X, B, 128 * r);

    for (i = 0; i < N; i++) {
        cc_memcpy(&T[i * (128 * r)], X, 128 * r);
        ccscrypt_blockmix_salsa8(X, Y, r);
    }

    for (i = 0; i < N; i++) {
        j = ccscrypt_integerify(B, r);

        cc_xor(128 * r, X, X, &T[j * (128 * r)]);
        ccscrypt_blockmix_salsa8(X, Y, r);
    }

    cc_memcpy(B, X, 128 * r);
}
