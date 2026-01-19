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

#ifndef _CORECRYPTO_CCRC2_LTC_INTERNAL_H_
#define _CORECRYPTO_CCRC2_LTC_INTERNAL_H_

#include <corecrypto/ccrc2.h>

struct ccrc2_ltc_ctx {
    uint32_t xkey[64];
};

int ccrc2_ltc_setup(const struct ccmode_ecb *ecb, ccecb_ctx *ctx, size_t key_nbytes, const void *key);

int ccrc2_ltc_ecb_decrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out);

int ccrc2_ltc_ecb_encrypt(const ccecb_ctx *ctx, size_t nblocks, const void *in, void *out);

#endif /* _CORECRYPTO_CCRC2_LTC_INTERNAL_H_ */
