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

#if __has_include(<libkern/crypto/register_crypto.h>)
#include <libkern/crypto/register_crypto.h>
#else
#include "register_crypto.h"
#endif

#include "../dummy/pdcrypto_dummy.h"

void cc_populate_fns_dummy(crypto_functions_t fns)
{
#if CCKEXT_TRACE
    printf("corecrypto: populating dummies for XNU\n");
#endif

    /* AES dummies */
    fns->ccaes_gcm_decrypt = &pdcaes_gcm_decrypt_dummy;
    fns->ccaes_gcm_encrypt = &pdcaes_gcm_encrypt_dummy;
    fns->ccaes_xts_decrypt = &pdcaes_xts_decrypt_dummy;
    fns->ccaes_xts_encrypt = &pdcaes_xts_encrypt_dummy;

    /* Padding dummies */
    fns->ccpad_xts_decrypt_fn = pdcpad_xts_encrypt_fn_dummy;
    fns->ccpad_xts_encrypt_fn = pdcpad_xts_decrypt_fn_dummy;

    /* RNG dummy */
    fns->ccrng_fn = &ccrng; /* I consider this a dummy because it returns the KPRNG. The **real** CCRNG is an NIST CTR DRBG using AES */

#if CCKEXT_TRACE
    printf("corecrypto: finished populating dummies.\n");
#endif
}
