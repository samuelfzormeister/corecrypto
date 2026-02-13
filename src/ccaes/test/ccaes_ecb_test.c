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

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_test_internal.h>

static struct ccmode_test_vector vecs[] = {
    {
        CCTEST_ATTRS_NONE,  // attrs
                            // key
                            // key length
                            // iv
                            // iv length
                            // text length
                            // pt
                            // ct
                            // aad
                            // aad length
    }
};

CCMODE_ECB_TEST_FACTORY(aes, encrypt, vecs, "LTC AES", ECBVarKey128, ltc_ecb_encrypt);
#if CCAES_INTEL_ASM
CCMODE_ECB_TEST_FACTORY(aes, encrypt, vecs, "INTEL OPT AES", ECBVarKey128, intel_ecb_encrypt_opt);
#endif
