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

#pragma mark - Known Answer Test section

static struct ccmode_test_vector CFB128GFSbox_encrypt_vectors[] = {
#include "vectors/CFB128GFSbox128_encrypt.inc"
#include "vectors/CFB128GFSbox192_encrypt.inc"
#include "vectors/CFB128GFSbox256_encrypt.inc"
};

static struct ccmode_test_vector CFB128GFSbox_decrypt_vectors[] = {
#include "vectors/CFB128GFSbox128_decrypt.inc"
#include "vectors/CFB128GFSbox192_decrypt.inc"
#include "vectors/CFB128GFSbox256_decrypt.inc"
};

static struct ccmode_test_vector CFB128KeySbox_encrypt_vectors[] = {
#include "vectors/CFB128KeySbox128_encrypt.inc"
#include "vectors/CFB128KeySbox192_encrypt.inc"
#include "vectors/CFB128KeySbox256_encrypt.inc"
};

static struct ccmode_test_vector CFB128KeySbox_decrypt_vectors[] = {
#include "vectors/CFB128KeySbox128_decrypt.inc"
#include "vectors/CFB128KeySbox192_decrypt.inc"
#include "vectors/CFB128KeySbox256_decrypt.inc"
};

static struct ccmode_test_vector CFB128VarKey_encrypt_vectors[] = {
#include "vectors/CFB128VarKey128_encrypt.inc"
#include "vectors/CFB128VarKey192_encrypt.inc"
#include "vectors/CFB128VarKey256_encrypt.inc"
};

static struct ccmode_test_vector CFB128VarKey_decrypt_vectors[] = {
#include "vectors/CFB128VarKey128_decrypt.inc"
#include "vectors/CFB128VarKey192_decrypt.inc"
#include "vectors/CFB128VarKey256_decrypt.inc"
};

static struct ccmode_test_vector CFB128VarTxt_encrypt_vectors[] = {
#include "vectors/CFB128VarTxt128_encrypt.inc"
#include "vectors/CFB128VarTxt192_encrypt.inc"
#include "vectors/CFB128VarTxt256_encrypt.inc"
};

static struct ccmode_test_vector CFB128VarTxt_decrypt_vectors[] = {
#include "vectors/CFB128VarTxt128_decrypt.inc"
#include "vectors/CFB128VarTxt192_decrypt.inc"
#include "vectors/CFB128VarTxt256_decrypt.inc"
};

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, encrypt, CFB128GFSbox_encrypt_vectors, 
                                gfsbox, "LTC backed AES CFB Encrypt (CFB128GFSbox)", 
                                ltc_cfb_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, encrypt, CFB128KeySbox_encrypt_vectors, 
                                keysbox, "LTC backed AES CFB Encrypt (CFB128KeySbox)", 
                                ltc_cfb_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, encrypt, CFB128VarKey_encrypt_vectors, 
                                varkey, "LTC backed AES CFB Encrypt (CFB128VarKey)", 
                                ltc_cfb_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, encrypt, CFB128VarTxt_encrypt_vectors, 
                                vartxt, "LTC backed AES CFB Encrypt (CFB128VarTxt)", 
                                ltc_cfb_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, decrypt, CFB128GFSbox_decrypt_vectors, 
                                gfsbox, "LTC backed AES CFB Decrypt (CFB128GFSbox)", 
                                ltc_cfb_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, decrypt, CFB128KeySbox_decrypt_vectors, 
                                keysbox, "LTC backed AES CFB Decrypt (CFB128KeySbox)", 
                                ltc_cfb_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, decrypt, CFB128VarKey_decrypt_vectors, 
                                varkey, "LTC backed AES CFB Decrypt (CFB128VarKey)", 
                                ltc_cfb_decrypt, ltc_ecb_decrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, decrypt, CFB128VarTxt_decrypt_vectors, 
                                vartxt, "LTC backed AES CFB Decrypt (CFB128VarTxt)", 
                                ltc_cfb_decrypt, ltc_ecb_decrypt);

#pragma mark - Multi-Block Test

static struct ccmode_test_vector CFB128MMT_encrypt_vectors[] = {
#include "vectors/CFB128MMT128_encrypt.inc"
#include "vectors/CFB128MMT192_encrypt.inc"
#include "vectors/CFB128MMT256_encrypt.inc"
};

static struct ccmode_test_vector CFB128MMT_decrypt_vectors[] = {
#include "vectors/CFB128MMT128_decrypt.inc"
#include "vectors/CFB128MMT192_decrypt.inc"
#include "vectors/CFB128MMT256_decrypt.inc"
};

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, encrypt, CFB128MMT_encrypt_vectors, 
                                mmt, "LTC backed AES CFB Encrypt (CFB128MMT)", 
                                ltc_cfb_encrypt, ltc_ecb_encrypt);

CCMODE_CONSTRUCTED_TEST_FACTORY(aes, cfb, decrypt, CFB128MMT_decrypt_vectors, 
                                mmt, "LTC backed AES CFB Encrypt (CFB128MMT)", 
                                ltc_cfb_decrypt, ltc_ecb_decrypt);
