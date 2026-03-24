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

static struct ccmode_test_vector cfb_encrypt_vectors[] = {
#include "vectors/CFB128GFSbox128_encrypt.inc"
#include "vectors/CFB128GFSbox192_encrypt.inc"
#include "vectors/CFB128GFSbox256_encrypt.inc"
#include "vectors/CFB128KeySbox128_encrypt.inc"
#include "vectors/CFB128KeySbox192_encrypt.inc"
#include "vectors/CFB128KeySbox256_encrypt.inc"
#include "vectors/CFB128VarKey128_encrypt.inc"
#include "vectors/CFB128VarKey192_encrypt.inc"
#include "vectors/CFB128VarKey256_encrypt.inc"
#include "vectors/CFB128VarTxt128_encrypt.inc"
#include "vectors/CFB128VarTxt192_encrypt.inc"
#include "vectors/CFB128VarTxt256_encrypt.inc"
#include "vectors/CFB128MMT128_encrypt.inc"
#include "vectors/CFB128MMT192_encrypt.inc"
#include "vectors/CFB128MMT256_encrypt.inc"
};

static struct ccmode_test_vector cfb_decrypt_vectors[] = {
#include "vectors/CFB128GFSbox128_decrypt.inc"
#include "vectors/CFB128GFSbox192_decrypt.inc"
#include "vectors/CFB128GFSbox256_decrypt.inc"
#include "vectors/CFB128KeySbox128_decrypt.inc"
#include "vectors/CFB128KeySbox192_decrypt.inc"
#include "vectors/CFB128KeySbox256_decrypt.inc"
#include "vectors/CFB128VarKey128_decrypt.inc"
#include "vectors/CFB128VarKey192_decrypt.inc"
#include "vectors/CFB128VarKey256_decrypt.inc"
#include "vectors/CFB128VarTxt128_decrypt.inc"
#include "vectors/CFB128VarTxt192_decrypt.inc"
#include "vectors/CFB128VarTxt256_decrypt.inc"
#include "vectors/CFB128MMT128_decrypt.inc"
#include "vectors/CFB128MMT192_decrypt.inc"
#include "vectors/CFB128MMT256_decrypt.inc"
};

CCMODE_DEFAULT_TEST_FACTORY(aes, cfb, encrypt, cfb_encrypt_vectors, "CFB AES Encrypt (Default)");
CCMODE_DEFAULT_TEST_FACTORY(aes, cfb, decrypt, cfb_decrypt_vectors, "CFB AES Decrypt (Default)");

//
// CFB8 is backed by ECB Encrypt.
//
#define ccaes_ecb_decrypt_mode ccaes_ecb_encrypt_mode

CCMODE_FACTORY_TEST_FACTORY(aes, cfb, encrypt, cfb_encrypt_vectors, "CFB AES Encrypt (Factory)");
CCMODE_FACTORY_TEST_FACTORY(aes, cfb, decrypt, cfb_decrypt_vectors, "CFB AES Decrypt (Factory)");
