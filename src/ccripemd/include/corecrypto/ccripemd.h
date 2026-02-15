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

#ifndef _CORECRYPTO_CCRIPEMD_H_
#define _CORECRYPTO_CCRIPEMD_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>

#define CCRIPEMD_BLOCK_SIZE  64

#define CCRMD160_OUTPUT_SIZE 20
#define CCRMD160_STATE_SIZE  20

#define ccoid_rmd160 ((unsigned char *)"\x06\x05\x2B\x24\x03\x02\x01")
#define ccoid_rmd160_len 7

extern const struct ccdigest_info ccrmd160_ltc_di;

#define ccrmd160_di ccrmd160_ltc_di

/*
 * RMD128, RMD256 and RMD320 were obsoleted in Apple's 2019 Fall releases (macOS Catalina, etc).
 *
 * For backwards-compatibility with programs and clients, keep the symbol but deprecate it for
 * when a client targets >= macOS 10.15.
 */

#define CCRMD128_OUTPUT_SIZE 16
#define CCRMD128_STATE_SIZE  16

#define ccoid_rmd128 ((unsigned char *)"\x06\x05\x2B\x24\x03\x02\x02")
#define ccoid_rmd128_len 7

extern const struct ccdigest_info ccrmd128_ltc_di cc_deprecate(13.0, 10.15, 13.0, 6.0, 4.0);

#define ccrmd128_di ccrmd128_ltc_di

#define CCRMD256_OUTPUT_SIZE 32
#define CCRMD256_STATE_SIZE  32

#define ccoid_rmd256 ((unsigned char *)"\x06\x05\x2B\x24\x03\x02\x03")
#define ccoid_rmd256_len 7

extern const struct ccdigest_info ccrmd256_ltc_di cc_deprecate(13.0, 10.15, 13.0, 6.0, 4.0);

#define ccrmd256_di ccrmd256_ltc_di

#define CCRMD320_OUTPUT_SIZE 40
#define CCRMD320_STATE_SIZE  40

/*
 * No OID for RMD320.
 */

extern const struct ccdigest_info ccrmd320_ltc_di cc_deprecate(13.0, 10.15, 13.0, 6.0, 4.0);

#define ccrmd320_di ccrmd320_ltc_di

#endif /* _CORECRYPTO_CCRIPEMD_H_ */
