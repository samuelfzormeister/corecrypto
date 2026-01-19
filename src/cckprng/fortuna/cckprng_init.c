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

#define __CORECRYPTO_EXPERIMENTAL_KPRNG__ 1

#include <corecrypto/cc_debug.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/cckprng.h>

#include <kern/panic_call.h>

#define CCKPRNG_PANIC_COND(cond, ...) if (!(cond)) { panic("cckprng: " __VA_ARGS__); }

void cckprng_init(struct cckprng_ctx *ctx, unsigned max_ngens, size_t entropybuf_nbytes, const void *entropybuf,
                  const uint32_t *entropybuf_nsamples, size_t seed_nbytes, const void *seed, size_t nonce_nbytes,
                  const void *nonce)
{
    cc_printf("KPRNG: Initializing with Generator count of %d", max_ngens);
    
    ctx->lock.group = lck_grp_alloc_init("cckprng", NULL);
    ctx->lock.mutex = lck_mtx_alloc_init(ctx->lock.group, NULL);
    
    CCKPRNG_PANIC_COND(ctx->lock.group != NULL, "Failed to ");
}
