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
#include <corecrypto/ccaes_test.h>

static struct ccmode_test_vector ofb_encrypt_vectors[] = {
#include "vectors/OFBGFSbox128_encrypt.inc"
#include "vectors/OFBGFSbox192_encrypt.inc"
#include "vectors/OFBGFSbox256_encrypt.inc"
#include "vectors/OFBKeySbox128_encrypt.inc"
#include "vectors/OFBKeySbox192_encrypt.inc"
#include "vectors/OFBKeySbox256_encrypt.inc"
#include "vectors/OFBVarKey128_encrypt.inc"
#include "vectors/OFBVarKey192_encrypt.inc"
#include "vectors/OFBVarKey256_encrypt.inc"
#include "vectors/OFBVarTxt128_encrypt.inc"
#include "vectors/OFBVarTxt192_encrypt.inc"
#include "vectors/OFBVarTxt256_encrypt.inc"
#include "vectors/OFBMMT128_encrypt.inc"
#include "vectors/OFBMMT192_encrypt.inc"
#include "vectors/OFBMMT256_encrypt.inc"
};

static struct ccmode_test_vector ofb_decrypt_vectors[] = {
#include "vectors/OFBGFSbox128_decrypt.inc"
#include "vectors/OFBGFSbox192_decrypt.inc"
#include "vectors/OFBGFSbox256_decrypt.inc"
#include "vectors/OFBKeySbox128_decrypt.inc"
#include "vectors/OFBKeySbox192_decrypt.inc"
#include "vectors/OFBKeySbox256_decrypt.inc"
#include "vectors/OFBVarKey128_decrypt.inc"
#include "vectors/OFBVarKey192_decrypt.inc"
#include "vectors/OFBVarKey256_decrypt.inc"
#include "vectors/OFBVarTxt128_decrypt.inc"
#include "vectors/OFBVarTxt192_decrypt.inc"
#include "vectors/OFBVarTxt256_decrypt.inc"
#include "vectors/OFBMMT128_decrypt.inc"
#include "vectors/OFBMMT192_decrypt.inc"
#include "vectors/OFBMMT256_decrypt.inc"
};

//
// OFB works both ways.
//
#define ccmode_factory_ofb_encrypt ccmode_factory_ofb_crypt
#define ccmode_factory_ofb_decrypt ccmode_factory_ofb_crypt

#define ccaes_ofb_encrypt_mode ccaes_ofb_crypt_mode
#define ccaes_ofb_decrypt_mode ccaes_ofb_crypt_mode

CCMODE_DEFAULT_TEST_FACTORY(aes, ofb, encrypt, ofb_encrypt_vectors, "OFB AES Encrypt (Default)");
CCMODE_DEFAULT_TEST_FACTORY(aes, ofb, decrypt, ofb_decrypt_vectors, "OFB AES Decrypt (Default)");

#define ccaes_ecb_decrypt_mode ccaes_ecb_encrypt_mode

CCMODE_FACTORY_TEST_FACTORY(aes, ofb, encrypt, ofb_encrypt_vectors, "OFB AES Encrypt (Factory)");
CCMODE_FACTORY_TEST_FACTORY(aes, ofb, decrypt, ofb_decrypt_vectors, "OFB AES Decrypt (Factory)");
