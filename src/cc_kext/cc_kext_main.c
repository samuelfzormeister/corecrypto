/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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

#include <mach/mach_types.h>
#include <sys/systm.h>

#if __has_include(<libkern/crypto/register_crypto.h>) && __has_include(<prng/random.h>)
#include <libkern/crypto/register_crypto.h>
#include <prng/random.h>
#else
#include "prng_random.h"
#include "register_crypto.h"
#endif

#include "../kprng/yarrow/yarrow.h"
#include <corecrypto/cckprng.h>

#if CORECRYPTO_KEXT_TEST
#include <corecrypto/cctest_priv.h>
#endif

struct crypto_functions cc_functions;

static const struct cckprng_funcs cc_kprng_fns = {
    .init = cckprng_init,
    .initgen = cckprng_initgen,
    .reseed = cckprng_reseed,
    .refresh = cckprng_refresh,
    .generate = cckprng_generate
};

static struct cckprng_ctx cc_kprng_ctx = {
    .prng = NULL,
    .bytes_since_entropy = 0,
    .bytes_generated = 0
};

/* cc_populate_fns.c && cc_populate_fns_dummy.c */
extern void cc_populate_fns(crypto_functions_t fns);
extern void cc_populate_fns_dummy(crypto_functions_t fns);

kern_return_t cc_kext_start(kmod_info_t *ki, void *d)
{
    printf("corecrypto: module start, built %s\n", __TIMESTAMP__);

#if CORECRYPTO_KEXT_TEST
    if (cctest_run_all() == 0) {
        cc_printf("corecrypto test: finished testing!\n");
    } else {
        panic("corecrypto: test failure!!!\n");
    }
#endif // CORECRYPTO_KEXT_TEST

    /* Populate our functions. */
    cc_populate_fns(&cc_functions);
    cc_populate_fns_dummy(&cc_functions);

    int ret = register_crypto_functions(&cc_functions);

    /* I should REALLY write the Fortuna derived KPRNG. clangd won't shut up about the yarrow library imported. */
    if (ret == -1) {
        printf("warning: corecrypto could not be registered. Did another crypto handler beat us to it?\n");
    } else {
        prng_error_status error = prngInitialize(&cc_kprng_ctx.prng);
        if (error != PRNG_SUCCESS) {
            panic("prngInitialize() failed with code %d", error);
        }

        register_and_init_prng(&cc_kprng_ctx, &cc_kprng_fns);
        printf("corecrypto: registered functions and prng.\n");
    }

    return KERN_SUCCESS;
}

kern_return_t cc_kext_stop(kmod_info_t *ki, void *d)
{
    return KERN_FAILURE;
}
