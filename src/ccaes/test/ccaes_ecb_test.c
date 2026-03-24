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

static struct ccmode_test_vector ecb_encrypt_vectors[] = {
#include "vectors/ECBGFSbox128_encrypt.inc"
#include "vectors/ECBGFSbox192_encrypt.inc"
#include "vectors/ECBGFSbox256_encrypt.inc"
#include "vectors/ECBKeySbox128_encrypt.inc"
#include "vectors/ECBKeySbox192_encrypt.inc"
#include "vectors/ECBKeySbox256_encrypt.inc"
#include "vectors/ECBVarKey128_encrypt.inc"
#include "vectors/ECBVarKey192_encrypt.inc"
#include "vectors/ECBVarKey256_encrypt.inc"
#include "vectors/ECBVarTxt128_encrypt.inc"
#include "vectors/ECBVarTxt192_encrypt.inc"
#include "vectors/ECBVarTxt256_encrypt.inc"
#include "vectors/ECBMMT128_encrypt.inc"
#include "vectors/ECBMMT192_encrypt.inc"
#include "vectors/ECBMMT256_encrypt.inc"
};

static struct ccmode_test_vector ecb_decrypt_vectors[] = {
#include "vectors/ECBGFSbox128_decrypt.inc"
#include "vectors/ECBGFSbox192_decrypt.inc"
#include "vectors/ECBGFSbox256_decrypt.inc"
#include "vectors/ECBKeySbox128_decrypt.inc"
#include "vectors/ECBKeySbox192_decrypt.inc"
#include "vectors/ECBKeySbox256_decrypt.inc"
#include "vectors/ECBVarKey128_decrypt.inc"
#include "vectors/ECBVarKey192_decrypt.inc"
#include "vectors/ECBVarKey256_decrypt.inc"
#include "vectors/ECBVarTxt128_decrypt.inc"
#include "vectors/ECBVarTxt192_decrypt.inc"
#include "vectors/ECBVarTxt256_decrypt.inc"
#include "vectors/ECBMMT128_decrypt.inc"
#include "vectors/ECBMMT192_decrypt.inc"
#include "vectors/ECBMMT256_decrypt.inc"
};

CCMODE_DEFAULT_TEST_FACTORY(aes, ecb, encrypt, ecb_encrypt_vectors, "AES Encrypt (Default)");
CCMODE_DEFAULT_TEST_FACTORY(aes, ecb, decrypt, ecb_decrypt_vectors, "AES Decrypt (Default)");

CCMODE_ECB_TEST_FACTORY(aes, encrypt, ecb_encrypt_vectors, "LTC AES Encrypt", ltc_ecb_encrypt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ecb_decrypt_vectors, "LTC AES Decrypt", ltc_ecb_decrypt);

#if CCAES_INTEL_ASM
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ecb_encrypt_vectors, "Intel Default ASM AES Encrypt", intel_ecb_encrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ecb_decrypt_vectors, "Intel Default AES Decrypt", intel_ecb_decrypt_opt);

CCMODE_ECB_TEST_FACTORY(aes, encrypt, ecb_encrypt_vectors, "Intel AESNI ASM AES Encrypt", intel_ecb_encrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ecb_decrypt_vectors, "Intel AESNI AES Decrypt", intel_ecb_decrypt_aesni);
#endif

