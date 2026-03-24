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

#ifndef _CORECRYPTO_CCSCRYPT_H_
#define _CORECRYPTO_CCSCRYPT_H_

#include <stdint.h>
#include <corecrypto/cc.h>

/*!
 * @group ccscrypt
 * The scrypt password-based key derivation function.
 *
 * See RFC 7914 for specifications
 * https://www.rfc-editor.org/rfc/rfc7914
 */

/*!
 * @function ccscrypt_storage_size
 * Calculate the amount of bytes required to perform the scrypt KDF.
 *
 * @param N     The cost factor
 * @param r     The block size
 * @param p     The parallelization factor
 *
 * @result      The number of bytes required.
 */
int64_t ccscrypt_storage_size(uint64_t N, uint32_t r, uint32_t p) CC_API_AVAILABLE_FALL_2019;

/*!
 * @function ccscrypt
 * Perform the scrypt PBKDF function.
 *
 * @param password_len      The length of the password
 * @param password          The password
 * @param salt_len          The length of the salt
 * @param salt              The salt to use
 * @param storage           The allocated memory space to operate in
 * @param N                 The cost factor
 * @param r                 The block size
 * @param p                 The parallelization factor
 * @param dk_len            The length of the derived key
 * @param dk                The derived key buffer
 *
 * @result                  CCERR_OK if everything went successfully.
 */
int ccscrypt(size_t password_len, const void *password,
             size_t salt_len, const void *salt,
             void *storage, 
             uint64_t N, uint32_t r, uint32_t p,
             size_t dk_len, void *dk) CC_API_AVAILABLE_FALL_2019;

#endif /* _CORECRYPTO_CCSCRYPT_H_ */
