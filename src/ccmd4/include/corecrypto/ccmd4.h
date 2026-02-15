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

#ifndef _CORECRYPTO_CCMD4_H_
#define _CORECRYPTO_CCMD4_H_

#include <corecrypto/ccdigest.h>

// MD4 interface

#define CCMD4_BLOCK_SIZE  64
#define CCMD4_OUTPUT_SIZE 16
#define CCMD4_STATE_SIZE  16

#define ccoid_md4 ((unsigned char *)"\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x04")
#define ccoid_md4_len 10

extern const struct ccdigest_info ccmd4_ltc_di;

#define ccmd4_di ccmd4_ltc_di

#endif /* _CORECRYPTO_CCMD4_H_ */
