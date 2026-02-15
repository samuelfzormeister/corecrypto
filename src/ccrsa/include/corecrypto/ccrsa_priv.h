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

#ifndef _CORECRYPTO_CCRSA_PRIV_H_
#define _CORECRYPTO_CCRSA_PRIV_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrsa.h>

/* Various non-descript functions I've found. */

/* PKCS#1 v1.5 functions */
int ccrsa_encrypt_eme_pkcs1v15(ccrsa_pub_ctx_t pub,
                               struct ccdigest_info *digest,
                               struct ccrng_state *rng,
                               size_t ct_len, void *ct,
                               size_t pt_len, const void *pt,
                               size_t tag_len, const void *tag);

int ccrsa_decrypt_eme_pkcs1v15(ccrsa_full_ctx_t pub,
                               struct ccdigest_info *digest,
                               struct ccrng_state *rng,
                               size_t pt_len, void *pt,
                               size_t ct_len, const void *ct,
                               size_t tag_len, const void *tag);

/* RSA OAEP functions. There's probably more I'm missing since I need my symbol dump. */
void ccrsa_oaep_encode(struct ccdigest_info *digest,
                       struct ccrng_state *rng,
                       size_t buffer_size, cc_unit *padding_buffer,
                       size_t data_len, const void *data);

int ccrsa_oaep_decode(struct ccdigest_info *digest,
                      size_t *plaintext_len, void *plaintext,
                      size_t msg_len, cc_unit *padding_buffer);

int ccrsa_encrypt_oaep(ccrsa_pub_ctx_t pub,
                       struct ccdigest_info *digest,
                       struct ccrng_state *rng,
                       size_t ct_len, void *ct,
                       size_t pt_len, const void *pt,
                       size_t tag_len, const void *tag);

#endif /* _CORECRYPTO_CCRSA_PRIV_H */
