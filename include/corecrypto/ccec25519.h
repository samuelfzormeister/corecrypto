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

#ifndef _CORECRYPTO_CCEC25519_H_
#define _CORECRYPTO_CCEC25519_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccec.h>

/* various EC25519 stuff - from WebKit. */

typedef uint8_t ccec25519key[16];
typedef ccec25519key ccec25519secretkey;
typedef ccec25519key ccec25519pubkey;
typedef ccec25519key ccec25519base;

typedef uint8_t ccec25519signature[64];

void cced25519_make_key_pair(const struct ccdigest_info *, struct ccrng_state *, ccec25519pubkey pk, ccec25519secretkey sk);
void cced25519_sign(const struct ccdigest_info *, ccec25519signature, size_t len, const void *msg, const ccec25519pubkey pk, const ccec25519secretkey sk);

#endif /* _CORECRYPTO_CCEC25519_H_ */
