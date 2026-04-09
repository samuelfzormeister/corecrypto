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

static struct ccmode_test_vector cbc_encrypt_vectors[] = {
#include "vectors/CBCGFSbox128_encrypt.inc"
#include "vectors/CBCGFSbox192_encrypt.inc"
#include "vectors/CBCGFSbox256_encrypt.inc"
#include "vectors/CBCKeySbox128_encrypt.inc"
#include "vectors/CBCKeySbox192_encrypt.inc"
#include "vectors/CBCKeySbox256_encrypt.inc"
#include "vectors/CBCVarKey128_encrypt.inc"
#include "vectors/CBCVarKey192_encrypt.inc"
#include "vectors/CBCVarKey256_encrypt.inc"
#include "vectors/CBCVarTxt128_encrypt.inc"
#include "vectors/CBCVarTxt192_encrypt.inc"
#include "vectors/CBCVarTxt256_encrypt.inc"
#include "vectors/CBCMMT128_encrypt.inc"
#include "vectors/CBCMMT192_encrypt.inc"
#include "vectors/CBCMMT256_encrypt.inc"
};

static struct ccmode_test_vector cbc_decrypt_vectors[] = {
#include "vectors/CBCGFSbox128_decrypt.inc"
#include "vectors/CBCGFSbox192_decrypt.inc"
#include "vectors/CBCGFSbox256_decrypt.inc"
#include "vectors/CBCKeySbox128_decrypt.inc"
#include "vectors/CBCKeySbox192_decrypt.inc"
#include "vectors/CBCKeySbox256_decrypt.inc"
#include "vectors/CBCVarKey128_decrypt.inc"
#include "vectors/CBCVarKey192_decrypt.inc"
#include "vectors/CBCVarKey256_decrypt.inc"
#include "vectors/CBCVarTxt128_decrypt.inc"
#include "vectors/CBCVarTxt192_decrypt.inc"
#include "vectors/CBCVarTxt256_decrypt.inc"
#include "vectors/CBCMMT128_decrypt.inc"
#include "vectors/CBCMMT192_decrypt.inc"
#include "vectors/CBCMMT256_decrypt.inc"
};

CCMODE_DEFAULT_TEST_FACTORY(aes, cbc, encrypt, cbc_encrypt_vectors, "CBC AES Encrypt (Default)");
CCMODE_DEFAULT_TEST_FACTORY(aes, cbc, decrypt, cbc_decrypt_vectors, "CBC AES Decrypt (Default)");

CCMODE_FACTORY_TEST_FACTORY(aes, cbc, encrypt, cbc_encrypt_vectors, "CBC AES Encrypt (Factory)");
CCMODE_FACTORY_TEST_FACTORY(aes, cbc, decrypt, cbc_decrypt_vectors, "CBC AES Decrypt (Factory)");

CCMODE_CBC_TEST_FACTORY(aes, encrypt, cbc_encrypt_vectors, "Gladman AES Encrypt", gladman_cbc_encrypt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, cbc_decrypt_vectors, "Gladman AES Decrypt", gladman_cbc_decrypt);

#if CCAES_INTEL_ASM
CCMODE_CBC_TEST_FACTORY(aes, encrypt, cbc_encrypt_vectors, "Intel Opt AES Encrypt", intel_cbc_encrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, cbc_decrypt_vectors, "Intel Opt AES Decrypt", intel_cbc_decrypt_opt);

CCMODE_CBC_TEST_FACTORY(aes, encrypt, cbc_encrypt_vectors, "Intel AESNI AES Encrypt", intel_cbc_encrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, cbc_decrypt_vectors, "Intel AESNI AES Decrypt", intel_cbc_decrypt_aesni);
#endif
