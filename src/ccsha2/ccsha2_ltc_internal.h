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

#ifndef _CORECRYPTO_CCSHA2_LTC_INTERNAL_H_
#define _CORECRYPTO_CCSHA2_LTC_INTERNAL_H_

#include <corecrypto/ccsha2.h>

extern const uint32_t ccsha224_initial_state[8];
extern const uint32_t ccsha256_initial_state[8];
extern const uint64_t ccsha384_initial_state[8];
extern const uint64_t ccsha512_initial_state[8];
extern const uint64_t ccsha512_224_initial_state[8];
extern const uint64_t ccsha512_256_initial_state[8];

extern const uint32_t ccsha256_K[64];
extern const uint64_t ccsha512_K[80];

extern void ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *data);
extern void ccsha512_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *data);
extern void ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest);

#endif
