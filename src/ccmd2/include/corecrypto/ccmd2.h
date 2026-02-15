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

#ifndef _CORECRYPTO_CCMD2_H_
#define _CORECRYPTO_CCMD2_H_

#include <corecrypto/ccdigest.h>

// MD2 interface

#define CCMD2_BLOCK_SIZE  16
#define CCMD2_OUTPUT_SIZE 16
#define CCMD2_STATE_SIZE  64

#define ccoid_md2 ((unsigned char *)"\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02")
#define ccoid_md2_len 10

// CommonCrypto uses the & operator on the digest function. I can only assume it returns the structure and not a pointer.

extern const struct ccdigest_info ccmd2_ltc_di;

// Apparently a macro???
// CommonCrypto uses it *like* one.
#define ccmd2_di ccmd2_ltc_di

#endif /* _CORECRYPTO_CCMD2_H_ */
