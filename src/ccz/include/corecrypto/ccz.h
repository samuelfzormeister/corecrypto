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

#ifndef _CORECRYPTO_CCZ_H_
#define _CORECRYPTO_CCZ_H_

#include <stdbool.h>
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>

/* bignum handling in C - that's what ccz is. */

/* hence why we have this structure... */
struct ccz_class {
    void *ctx;
    void *(*ccz_alloc)(void *ctx, size_t size);
    void *(*ccz_realloc)(void *ctx, size_t oldsize, void *p, size_t newsize);
    void (*ccz_free)(void *ctx, size_t size, void *p);
};
/* ^ i guess this could be for abstract APIs, CommonCrypto uses it for a reason after all. maybe EFI uses it somewhere so it can't use the standard malloc? */

struct {
    struct ccz_class *ccz_class; /* I think? */
    cc_size n;
    cc_unit u[];
} typedef ccz;

void ccz_init(struct ccz_class *cl, ccz *r);

void ccz_free(ccz *z);

void ccz_zero(ccz *z);

size_t ccz_size(ccz *z);

size_t ccz_bitlen(ccz *z);

void ccz_set(ccz *r, const ccz *s);

bool ccz_is_one(ccz *z);

bool ccz_is_prime(ccz *z, size_t rounds);

bool ccz_is_negative(ccz *z);

bool ccz_is_zero(ccz *z);

#endif /* _CORECRYPTO_CCZ_H_ */
