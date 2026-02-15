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

static struct ccmode_test_vector ECBGFSbox_encrypt_vectors[] = {
#include "vectors/ECBGFSbox128_encrypt.inc"
#include "vectors/ECBGFSbox192_encrypt.inc"
#include "vectors/ECBGFSbox256_encrypt.inc"
};

static struct ccmode_test_vector ECBGFSbox_decrypt_vectors[] = {
#include "vectors/ECBGFSbox128_decrypt.inc"
#include "vectors/ECBGFSbox192_decrypt.inc"
#include "vectors/ECBGFSbox256_decrypt.inc"
};

static struct ccmode_test_vector ECBKeySbox_encrypt_vectors[] = {
#include "vectors/ECBKeySbox128_encrypt.inc"
#include "vectors/ECBKeySbox192_encrypt.inc"
#include "vectors/ECBKeySbox256_encrypt.inc"
};

static struct ccmode_test_vector ECBKeySbox_decrypt_vectors[] = {
#include "vectors/ECBKeySbox128_decrypt.inc"
#include "vectors/ECBKeySbox192_decrypt.inc"
#include "vectors/ECBKeySbox256_decrypt.inc"
};

static struct ccmode_test_vector ECBVarKey_encrypt_vectors[] = {
#include "vectors/ECBVarKey128_encrypt.inc"
#include "vectors/ECBVarKey192_encrypt.inc"
#include "vectors/ECBVarKey256_encrypt.inc"
};

static struct ccmode_test_vector ECBVarKey_decrypt_vectors[] = {
#include "vectors/ECBVarKey128_decrypt.inc"
#include "vectors/ECBVarKey192_decrypt.inc"
#include "vectors/ECBVarKey256_decrypt.inc"
};

static struct ccmode_test_vector ECBVarTxt_encrypt_vectors[] = {
#include "vectors/ECBVarTxt128_encrypt.inc"
#include "vectors/ECBVarTxt192_encrypt.inc"
#include "vectors/ECBVarTxt256_encrypt.inc"
};

static struct ccmode_test_vector ECBVarTxt_decrypt_vectors[] = {
#include "vectors/ECBVarTxt128_decrypt.inc"
#include "vectors/ECBVarTxt192_decrypt.inc"
#include "vectors/ECBVarTxt256_decrypt.inc"
};

CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBGFSbox_encrypt_vectors, "LTC AES Encrypt (ECBGFSbox)", ecbgfsbox, ltc_ecb_encrypt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBKeySbox_encrypt_vectors, "LTC AES Encrypt (ECBKeySbox)", ecbkeysbox, ltc_ecb_encrypt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarKey_encrypt_vectors, "LTC AES Encrypt (ECBVarKey)", ecbvarkey, ltc_ecb_encrypt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarTxt_encrypt_vectors, "LTC AES Encrypt (ECBVarTxt)", ecbvartxt, ltc_ecb_encrypt);

CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBGFSbox_decrypt_vectors, "LTC AES Decrypt (ECBGFSbox)", ecbgfsbox, ltc_ecb_decrypt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBKeySbox_decrypt_vectors, "LTC AES Decrypt (ECBKeySbox)", ecbkeysbox, ltc_ecb_decrypt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarKey_decrypt_vectors, "LTC AES Decrypt (ECBVarKey)", ecbvarkey, ltc_ecb_decrypt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarTxt_decrypt_vectors, "LTC AES Decrypt (ECBVarTxt)", ecbvartxt, ltc_ecb_decrypt);

#if CCAES_INTEL_ASM
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBGFSbox_encrypt_vectors, "Intel Default ASM AES Encrypt (ECBGFSbox)", ecbgfsbox, intel_ecb_encrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBKeySbox_encrypt_vectors, "Intel Default ASM AES Encrypt (ECBKeySbox)", ecbkeysbox, intel_ecb_encrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarKey_encrypt_vectors, "Intel Default ASM AES Encrypt (ECBVarKey)", ecbvarkey, intel_ecb_encrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarTxt_encrypt_vectors, "Intel Default ASM AES Encrypt (ECBVarTxt)", ecbvartxt, intel_ecb_encrypt_opt);

CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBGFSbox_decrypt_vectors, "Intel Default ASM AES Decrypt (ECBGFSbox)", ecbgfsbox, intel_ecb_decrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBKeySbox_decrypt_vectors, "Intel Default ASM AES Decrypt (ECBKeySbox)", ecbkeysbox, intel_ecb_decrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarKey_decrypt_vectors, "Intel Default ASM AES Decrypt (ECBVarKey)", ecbvarkey, intel_ecb_decrypt_opt);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarTxt_decrypt_vectors, "Intel Default ASM AES Decrypt (ECBVarTxt)", ecbvartxt, intel_ecb_decrypt_opt);

CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBGFSbox_encrypt_vectors, "Intel AES-NI AES Encrypt (ECBGFSbox)", ecbgfsbox, intel_ecb_encrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBKeySbox_encrypt_vectors, "Intel AES-NI AES Encrypt (ECBKeySbox)", ecbkeysbox, intel_ecb_encrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarKey_encrypt_vectors, "Intel AES-NI AES Encrypt (ECBVarKey)", ecbvarkey, intel_ecb_encrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, encrypt, ECBVarTxt_encrypt_vectors, "Intel AES-NI AES Encrypt (ECBVarTxt)", ecbvartxt, intel_ecb_encrypt_aesni);

CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBGFSbox_decrypt_vectors, "Intel AES-NI AES Decrypt (ECBGFSbox)", ecbgfsbox, intel_ecb_decrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBKeySbox_decrypt_vectors, "Intel AES-NI AES Decrypt (ECBKeySbox)", ecbkeysbox, intel_ecb_decrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarKey_decrypt_vectors, "Intel AES-NI AES Decrypt (ECBVarKey)", ecbvarkey, intel_ecb_decrypt_aesni);
CCMODE_ECB_TEST_FACTORY(aes, decrypt, ECBVarTxt_decrypt_vectors, "Intel AES-NI AES Decrypt (ECBVarTxt)", ecbvartxt, intel_ecb_decrypt_aesni);
#endif
