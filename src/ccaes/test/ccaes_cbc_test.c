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

static struct ccmode_test_vector CBCGFSbox_encrypt_vectors[] = {
#include "vectors/CBCGFSbox128_encrypt.inc"
#include "vectors/CBCGFSbox192_encrypt.inc"
#include "vectors/CBCGFSbox256_encrypt.inc"
};

static struct ccmode_test_vector CBCGFSbox_decrypt_vectors[] = {
#include "vectors/CBCGFSbox128_decrypt.inc"
#include "vectors/CBCGFSbox192_decrypt.inc"
#include "vectors/CBCGFSbox256_decrypt.inc"
};

static struct ccmode_test_vector CBCKeySbox_encrypt_vectors[] = {
#include "vectors/CBCKeySbox128_encrypt.inc"
#include "vectors/CBCKeySbox192_encrypt.inc"
#include "vectors/CBCKeySbox256_encrypt.inc"
};

static struct ccmode_test_vector CBCKeySbox_decrypt_vectors[] = {
#include "vectors/CBCKeySbox128_decrypt.inc"
#include "vectors/CBCKeySbox192_decrypt.inc"
#include "vectors/CBCKeySbox256_decrypt.inc"
};

static struct ccmode_test_vector CBCVarKey_encrypt_vectors[] = {
#include "vectors/CBCVarKey128_encrypt.inc"
#include "vectors/CBCVarKey192_encrypt.inc"
#include "vectors/CBCVarKey256_encrypt.inc"
};

static struct ccmode_test_vector CBCVarKey_decrypt_vectors[] = {
#include "vectors/CBCVarKey128_decrypt.inc"
#include "vectors/CBCVarKey192_decrypt.inc"
#include "vectors/CBCVarKey256_decrypt.inc"
};

static struct ccmode_test_vector CBCVarTxt_encrypt_vectors[] = {
#include "vectors/CBCVarTxt128_encrypt.inc"
#include "vectors/CBCVarTxt192_encrypt.inc"
#include "vectors/CBCVarTxt256_encrypt.inc"
};

static struct ccmode_test_vector CBCVarTxt_decrypt_vectors[] = {
#include "vectors/CBCVarTxt128_decrypt.inc"
#include "vectors/CBCVarTxt192_decrypt.inc"
#include "vectors/CBCVarTxt256_decrypt.inc"
};

CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCGFSbox_encrypt_vectors, "Gladman AES Encrypt (CBCGFSbox)", gfsbox, gladman_cbc_encrypt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCKeySbox_encrypt_vectors, "Gladman AES Encrypt (CBCKeySbox)", keysbox, gladman_cbc_encrypt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarKey_encrypt_vectors, "Gladman AES Encrypt (CBCVarKey)", varkey, gladman_cbc_encrypt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarTxt_encrypt_vectors, "Gladman AES Encrypt (CBCVarTxt)", vartxt, gladman_cbc_encrypt);

CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCGFSbox_decrypt_vectors, "Gladman AES Decrypt (CBCGFSbox)", gfsbox, gladman_cbc_decrypt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCKeySbox_decrypt_vectors, "Gladman AES Decrypt (CBCKeySbox)", keysbox, gladman_cbc_decrypt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarKey_decrypt_vectors, "Gladman AES Decrypt (CBCVarKey)", varkey, gladman_cbc_decrypt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarTxt_decrypt_vectors, "Gladman AES Decrypt (CBCVarTxt)", vartxt, gladman_cbc_decrypt);

#if CCAES_INTEL_ASM
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCGFSbox_encrypt_vectors, "Intel Default ASM AES-CBC Encrypt (CBCGFSbox)", gfsbox, intel_cbc_encrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCKeySbox_encrypt_vectors, "Intel Default ASM AES-CBC Encrypt (CBCKeySbox)", keysbox, intel_cbc_encrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarKey_encrypt_vectors, "Intel Default ASM AES-CBC Encrypt (CBCVarKey)", varkey, intel_cbc_encrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarTxt_encrypt_vectors, "Intel Default ASM AES-CBC Encrypt (CBCVarTxt)", vartxt, intel_cbc_encrypt_opt);

CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCGFSbox_decrypt_vectors, "Intel Default ASM AES-CBC Decrypt (CBCGFSbox)", gfsbox, intel_cbc_decrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCKeySbox_decrypt_vectors, "Intel Default ASM AES-CBC Decrypt (CBCKeySbox)", keysbox, intel_cbc_decrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarKey_decrypt_vectors, "Intel Default ASM AES-CBC Decrypt (CBCVarKey)", varkey, intel_cbc_decrypt_opt);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarTxt_decrypt_vectors, "Intel Default ASM AES-CBC Decrypt (CBCVarTxt)", vartxt, intel_cbc_decrypt_opt);

CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCGFSbox_encrypt_vectors, "Intel AES-NI AES-CBC Encrypt (CBCGFSbox)", gfsbox, intel_cbc_encrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCKeySbox_encrypt_vectors, "Intel AES-NI AES-CBC Encrypt (CBCKeySbox)", keysbox, intel_cbc_encrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarKey_encrypt_vectors, "Intel AES-NI AES-CBC Encrypt (CBCVarKey)", varkey, intel_cbc_encrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, encrypt, CBCVarTxt_encrypt_vectors, "Intel AES-NI AES-CBC Encrypt (CBCVarTxt)", vartxt, intel_cbc_encrypt_aesni);

CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCGFSbox_decrypt_vectors, "Intel AES-NI AES-CBC Decrypt (CBCGFSbox)", gfsbox, intel_cbc_decrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCKeySbox_decrypt_vectors, "Intel AES-NI AES-CBC Decrypt (CBCKeySbox)", keysbox, intel_cbc_decrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarKey_decrypt_vectors, "Intel AES-NI AES-CBC Decrypt (CBCVarKey)", varkey, intel_cbc_decrypt_aesni);
CCMODE_CBC_TEST_FACTORY(aes, decrypt, CBCVarTxt_decrypt_vectors, "Intel AES-NI AES-CBC Decrypt (CBCVarTxt)", vartxt, intel_cbc_decrypt_aesni);
#endif
