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

#ifndef _CORECRYPTO_CCAES_LTC_INTERNAL_H_
#define _CORECRYPTO_CCAES_LTC_INTERNAL_H_

#include <corecrypto/ccaes.h>

typedef struct ltc_rijndael_key {
    uint32_t eK[60], dK[60];
    int Nr;
} ltc_rijndael_keysched;

extern int ccaes_ltc_init(const unsigned char *key, int keylen, int num_rounds, ccecb_ctx *skey);
extern int ccaes_ltc_ecb_encrypt(const unsigned char *pt, unsigned char *ct, ccecb_ctx *skey);
extern int ccaes_ltc_ecb_decrypt(const unsigned char *ct, unsigned char *pt, ccecb_ctx *skey);

#endif /* _CORECRYPTO_CCAES_LTC_INTERNAL_H_ */
