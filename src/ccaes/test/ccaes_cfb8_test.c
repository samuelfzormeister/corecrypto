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
#include <corecrypto/cctest_aes.h>

#pragma mark - Known Answer Test section

static struct ccmode_test_vector CFB8GFSbox_encrypt_vectors[] = {
#include "vectors/CFB8GFSbox128_encrypt.inc"
#include "vectors/CFB8GFSbox192_encrypt.inc"
#include "vectors/CFB8GFSbox256_encrypt.inc"
};

static struct ccmode_test_vector CFB8GFSbox_decrypt_vectors[] = {
#include "vectors/CFB8GFSbox128_decrypt.inc"
#include "vectors/CFB8GFSbox192_decrypt.inc"
#include "vectors/CFB8GFSbox256_decrypt.inc"
};

static struct ccmode_test_vector CFB8KeySbox_encrypt_vectors[] = {
#include "vectors/CFB8KeySbox128_encrypt.inc"
#include "vectors/CFB8KeySbox192_encrypt.inc"
#include "vectors/CFB8KeySbox256_encrypt.inc"
};

static struct ccmode_test_vector CFB8KeySbox_decrypt_vectors[] = {
#include "vectors/CFB8KeySbox128_decrypt.inc"
#include "vectors/CFB8KeySbox192_decrypt.inc"
#include "vectors/CFB8KeySbox256_decrypt.inc"
};

static struct ccmode_test_vector CFB8VarKey_encrypt_vectors[] = {
#include "vectors/CFB8VarKey128_encrypt.inc"
#include "vectors/CFB8VarKey192_encrypt.inc"
#include "vectors/CFB8VarKey256_encrypt.inc"
};

static struct ccmode_test_vector CFB8VarKey_decrypt_vectors[] = {
#include "vectors/CFB8VarKey128_decrypt.inc"
#include "vectors/CFB8VarKey192_decrypt.inc"
#include "vectors/CFB8VarKey256_decrypt.inc"
};

static struct ccmode_test_vector CFB8VarTxt_encrypt_vectors[] = {
#include "vectors/CFB8VarTxt128_encrypt.inc"
#include "vectors/CFB8VarTxt192_encrypt.inc"
#include "vectors/CFB8VarTxt256_encrypt.inc"
};

static struct ccmode_test_vector CFB8VarTxt_decrypt_vectors[] = {
#include "vectors/CFB8VarTxt128_decrypt.inc"
#include "vectors/CFB8VarTxt192_decrypt.inc"
#include "vectors/CFB8VarTxt256_decrypt.inc"
};

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8GFSbox_encrypt_vectors, 
                                gfsbox, "LTC backed AES CFB8 Encrypt (CFB8GFSbox)", 
                                ltc_cfb8_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8KeySbox_encrypt_vectors, 
                                keysbox, "LTC backed AES CFB8 Encrypt (CFB8KeySbox)", 
                                ltc_cfb8_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarKey_encrypt_vectors, 
                                varkey, "LTC backed AES CFB8 Encrypt (CFB8VarKey)", 
                                ltc_cfb8_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarTxt_encrypt_vectors, 
                                vartxt, "LTC backed AES CFB8 Encrypt (CFB8VarTxt)", 
                                ltc_cfb8_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8GFSbox_decrypt_vectors, 
                                gfsbox, "LTC backed AES CFB8 Decrypt (CFB8GFSbox)", 
                                ltc_cfb8_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8KeySbox_decrypt_vectors, 
                                keysbox, "LTC backed AES CFB8 Decrypt (CFB8KeySbox)", 
                                ltc_cfb8_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarKey_decrypt_vectors, 
                                varkey, "LTC backed AES CFB8 Decrypt (CFB8VarKey)", 
                                ltc_cfb8_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarTxt_decrypt_vectors, 
                                vartxt, "LTC backed AES CFB8 Decrypt (CFB8VarTxt)", 
                                ltc_cfb8_decrypt, ltc_ecb_decrypt);

#if CCAES_INTEL_ASM
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8GFSbox_encrypt_vectors,
                                gfsbox, "Intel ASM backed AES CFB Encrypt (CFB8GFSbox)",
                                intel_cfb8_encrypt_opt, intel_ecb_encrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8KeySbox_encrypt_vectors,
                                keysbox, "Intel ASM backed AES CFB Encrypt (CFB8KeySbox)",
                                intel_cfb8_encrypt_opt, intel_ecb_encrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarKey_encrypt_vectors,
                                varkey, "Intel ASM backed AES CFB Encrypt (CFB8VarKey)",
                                intel_cfb8_encrypt_opt, intel_ecb_encrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarTxt_encrypt_vectors,
                                vartxt, "Intel ASM backed AES CFB Encrypt (CFB8VarTxt)",
                                intel_cfb8_encrypt_opt, intel_ecb_encrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8GFSbox_decrypt_vectors,
                                gfsbox, "Intel ASM backed AES CFB Decrypt (CFB8GFSbox)",
                                intel_cfb8_decrypt_opt, intel_ecb_decrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8KeySbox_decrypt_vectors,
                                keysbox, "Intel ASM backed AES CFB Decrypt (CFB8KeySbox)",
                                intel_cfb8_decrypt_opt, intel_ecb_decrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarKey_decrypt_vectors,
                                varkey, "Intel ASM backed AES CFB Decrypt (CFB8VarKey)",
                                intel_cfb8_decrypt_opt, intel_ecb_decrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarTxt_decrypt_vectors,
                                vartxt, "Intel ASM backed AES CFB Decrypt (CFB8VarTxt)",
                                intel_cfb8_decrypt_opt, intel_ecb_decrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8GFSbox_encrypt_vectors,
                                gfsbox, "Intel AES-NI backed AES CFB Encrypt (CFB8GFSbox)",
                                intel_cfb8_encrypt_aesni, intel_ecb_encrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8KeySbox_encrypt_vectors,
                                keysbox, "Intel AES-NI backed AES CFB Encrypt (CFB8KeySbox)",
                                intel_cfb8_encrypt_aesni, intel_ecb_encrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarKey_encrypt_vectors,
                                varkey, "Intel AES-NI backed AES CFB Encrypt (CFB8VarKey)",
                                intel_cfb8_encrypt_aesni, intel_ecb_encrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8VarTxt_encrypt_vectors,
                                vartxt, "Intel AES-NI backed AES CFB Encrypt (CFB8VarTxt)",
                                intel_cfb8_encrypt_aesni, intel_ecb_encrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8GFSbox_decrypt_vectors,
                                gfsbox, "Intel AES-NI backed AES CFB Decrypt (CFB8GFSbox)",
                                intel_cfb8_decrypt_aesni, intel_ecb_decrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8KeySbox_decrypt_vectors,
                                keysbox, "Intel AES-NI backed AES CFB Decrypt (CFB8KeySbox)",
                                intel_cfb8_decrypt_aesni, intel_ecb_decrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarKey_decrypt_vectors,
                                varkey, "Intel AES-NI backed AES CFB Decrypt (CFB8VarKey)",
                                intel_cfb8_decrypt_aesni, intel_ecb_decrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8VarTxt_decrypt_vectors,
                                vartxt, "Intel AES-NI backed AES CFB Decrypt (CFB8VarTxt)",
                                intel_cfb8_decrypt_aesni, intel_ecb_decrypt_aesni);
#endif

#pragma mark - Multi-Block Test

static struct ccmode_test_vector CFB8MMT_encrypt_vectors[] = {
#include "vectors/CFB8MMT128_encrypt.inc"
#include "vectors/CFB8MMT192_encrypt.inc"
#include "vectors/CFB8MMT256_encrypt.inc"
};

static struct ccmode_test_vector CFB8MMT_decrypt_vectors[] = {
#include "vectors/CFB8MMT128_decrypt.inc"
#include "vectors/CFB8MMT192_decrypt.inc"
#include "vectors/CFB8MMT256_decrypt.inc"
};

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8MMT_encrypt_vectors, 
                                mmt, "LTC backed AES CFB8 Encrypt (CFB8MMT)", 
                                ltc_cfb8_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8MMT_decrypt_vectors, 
                                mmt, "LTC backed AES CFB8 Encrypt (CFB8MMT)", 
                                ltc_cfb8_decrypt, ltc_ecb_decrypt);

#if CCAES_INTEL_ASM
CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8MMT_encrypt_vectors,
                                mmt, "Intel ASM backed AES CFB Encrypt (CFB128MMT)",
                                intel_cfb8_encrypt_opt, intel_ecb_encrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8MMT_decrypt_vectors,
                                mmt, "Intel ASM backed AES CFB Encrypt (CFB128MMT)",
                                intel_cfb8_decrypt_opt, intel_ecb_decrypt_opt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, encrypt, CFB8MMT_encrypt_vectors,
                                mmt, "Intel AES-NI backed AES CFB Encrypt (CFB128MMT)",
                                intel_cfb8_encrypt_aesni, intel_ecb_encrypt_aesni);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb8, decrypt, CFB8MMT_decrypt_vectors,
                                mmt, "Intel AES-NI backed AES CFB Encrypt (CFB128MMT)",
                                intel_cfb8_decrypt_aesni, intel_ecb_decrypt_aesni);
#endif
