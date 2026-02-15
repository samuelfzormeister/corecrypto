/*
 * Copyright (C) 2025 The PureDarwin Project, All rights reserved.
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

#ifndef _CORECRYPTO_CCBLOWFISH_H_
#define _CORECRYPTO_CCBLOWFISH_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccmode.h>

#define CCBLOWFISH_BLOCK_SIZE 8
#define CCBLOWFISH_MIN_KEY_SIZE 8
#define CCBLOWFISH_MAX_KEY_SIZE 72

const struct ccmode_ecb *ccblowfish_ecb_encrypt_mode(void);
const struct ccmode_ecb *ccblowfish_ecb_decrypt_mode(void);

const struct ccmode_cbc *ccblowfish_cbc_encrypt_mode(void);
const struct ccmode_cbc *ccblowfish_cbc_decrypt_mode(void);

const struct ccmode_cfb *ccblowfish_cfb_encrypt_mode(void);
const struct ccmode_cfb *ccblowfish_cfb_decrypt_mode(void);

const struct ccmode_cfb8 *ccblowfish_cfb8_encrypt_mode(void);
const struct ccmode_cfb8 *ccblowfish_cfb8_decrypt_mode(void);

const struct ccmode_ctr *ccblowfish_ctr_crypt_mode(void);

const struct ccmode_ofb *ccblowfish_ofb_encrypt_mode(void);
const struct ccmode_ofb *ccblowfish_ofb_decrypt_mode(void);

#endif /* _CORECRYPTO_CCBLOWFISH_H_ */
