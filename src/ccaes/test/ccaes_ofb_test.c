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

static struct ccmode_test_vector OFBMMT_encrypt_vectors[] = {
#include "vectors/OFBMMT128_encrypt.inc"
#include "vectors/OFBMMT192_encrypt.inc"
#include "vectors/OFBMMT256_encrypt.inc"
};

static struct ccmode_test_vector OFBMMT_decrypt_vectors[] = {
#include "vectors/OFBMMT128_decrypt.inc"
#include "vectors/OFBMMT192_decrypt.inc"
#include "vectors/OFBMMT256_decrypt.inc"
};

//
// OFB works both ways.
//
#define ccmode_factory_ofb_encrypt ccmode_factory_ofb_crypt
#define ccmode_factory_ofb_decrypt ccmode_factory_ofb_crypt

/* great way to test the default ccmode logic, by using it as the driver for mode testing. */
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, ofb, encrypt, OFBMMT_encrypt_vectors, mmt, "OFB (LTC) AES Encrypt MMT", ltc_ofb_encrypt, ltc_ecb_encrypt);
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, ofb, decrypt, OFBMMT_decrypt_vectors, mmt, "OFB (LTC) AES Decrypt MMT", ltc_ofb_decrypt, ltc_ecb_decrypt);

#if CCAES_INTEL_ASM
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, ofb, encrypt, OFBMMT_encrypt_vectors, mmt, "OFB (LTC) AES Encrypt MMT", intel_ofb_encrypt_opt, intel_ecb_encrypt_opt);
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, ofb, decrypt, OFBMMT_decrypt_vectors, mmt, "OFB (LTC) AES Decrypt MMT", intel_ofb_decrypt_opt, intel_ecb_decrypt_opt);
#endif
