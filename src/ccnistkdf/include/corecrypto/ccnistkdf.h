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

#ifndef _CORECRYPTO_CCNISTKDF_H_
#define _CORECRYPTO_CCNISTKDF_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cccmac.h>

/*!
 * @group ccnistkdf
 *
 * @abstract Implementation of the NIST KDF functions
 *
 * @discussion Look at NIST specification SP800-108r1 for details
 */

/*!
 * @function   ccnistkdf_ctr_hmac
 * @abstract   The NIST KDF in Counter mode, using HMAC.
 *
 * @param   digest       Digest to use for HMAC.
 * @param   key_len      Length of the key Derivation Key
 * @param   key          The key derivation key
 * @param   label_len    Length of the Label
 * @param   label        The label variable of the NIST KDF function.
 * @param   context_len  Length of the context
 * @param   context      The context variable of the NIST KDF function.
 * @param   derived_len  The length of the derived key
 * @param   derived_key  The derived key
 *
 * @result     0 if successful.
 */
int ccnistkdf_ctr_hmac(struct ccdigest_info *digest,
                       size_t key_len, const void *key,
                       size_t label_len, const void *label,
                       size_t context_len, const void *context,
                       size_t derived_len, void *derived_key);

/*!
 * @function   ccnistkdf_ctr_cmac
 * @abstract   The NIST KDF in Counter mode, using CMAC.
 *
 * @param   cbc          AES-CBC mode to use for CMAC.
 * @param   key_len      Length of the key Derivation Key
 * @param   key          The key derivation key
 * @param   label_len    Length of the Label
 * @param   label        The label variable of the NIST KDF function.
 * @param   context_len  Length of the context
 * @param   context      The context variable of the NIST KDF function.
 * @param   derived_len  The length of the derived key
 * @param   derived_key  The derived key
 *
 * @result     0 if successful.
 */
int ccnistkdf_ctr_cmac(struct ccmode_cbc *cbc,
                       size_t key_len, const void *key,
                       size_t label_len, const void *label,
                       size_t context_len, const void *context,
                       size_t derived_len, void *derived_key);

#endif /* _CORECRYPTO_CCNISTKDF_H_ */
