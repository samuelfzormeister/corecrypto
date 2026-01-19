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

#ifndef _CORECRYPTO_CCRC4_EAY_INTERNAL_H_
#define _CORECRYPTO_CCRC4_EAY_INTERNAL_H_

#include <corecrypto/ccrc4.h>

typedef uint32_t RC4_INT;

/* and we'll map to unique function names to avoid collisions with libcrypto */
#define RC4_set_key eay_RC4_set_key
#define RC4         eay_RC4

#define RC4_MIN_KEY_SIZE_BYTES 1
#define RC4_MAX_KEY_SIZE_BYTES 512

typedef struct rc4_key_st {
    RC4_INT x, y;
    RC4_INT data[256];
} RC4_KEY;

void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, unsigned long len, const unsigned char *indata,
         unsigned char *outdata);

#endif /* _CORECRYPTO_CCRC4_EAY_INTERNAL_H_ */
