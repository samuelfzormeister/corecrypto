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

#ifndef _CORECRYPTO_CCSRP_H_
#define _CORECRYPTO_CCSRP_H_

#include <stdbool.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>

/* SRP related functions. */

/*

0000000000070dcf T _ccsrp_client_process_challenge
0000000000070cee T _ccsrp_client_start_authentication
00000000000717b5 T _ccsrp_client_verify_session
000000000003a801 t _ccsrp_digest_ccn
00000000000719c9 t _ccsrp_digest_ccn
0000000000072961 t _ccsrp_digest_ccn
00000000000741b3 t _ccsrp_digest_ccn
0000000000071806 t _ccsrp_digest_ccn_ccn
000000000007279e t _ccsrp_digest_ccn_ccn
0000000000073ff0 t _ccsrp_digest_ccn_ccn
0000000000071926 t _ccsrp_digest_update_ccn
00000000000728be t _ccsrp_digest_update_ccn
0000000000074110 t _ccsrp_digest_update_ccn
0000000000071684 t _ccsrp_generate_H_AMK
0000000000072588 t _ccsrp_generate_H_AMK
0000000000073ebf t _ccsrp_generate_H_AMK
000000000003a777 t _ccsrp_generate_K_from_S
000000000007143c t _ccsrp_generate_M
0000000000072340 t _ccsrp_generate_M
0000000000073c77 t _ccsrp_generate_M
0000000000071205 t _ccsrp_generate_client_S
0000000000073a40 t _ccsrp_generate_client_S
0000000000071add T _ccsrp_generate_salt_and_verification
000000000007220e t _ccsrp_generate_server_S
000000000007390e t _ccsrp_generate_server_S
0000000000071f11 t _ccsrp_generate_server_pubkey
00000000000737ae t _ccsrp_generate_server_pubkey
0000000000071b47 T _ccsrp_generate_verifier
000000000007109f t _ccsrp_generate_x
0000000000071c6e t _ccsrp_generate_x
0000000000073648 t _ccsrp_generate_x
0000000000070b31 T _ccsrp_gp_rfc5054_1024
0000000000070b4b T _ccsrp_gp_rfc5054_2048
000000000006033b T _ccsrp_gp_rfc5054_3072
0000000000070b65 T _ccsrp_gp_rfc5054_4096
0000000000070c0e T _ccsrp_gp_rfc5054_8192
000000000003aa1f t _ccsrp_mgf
0000000000072071 T _ccsrp_server_compute_session
0000000000071dd4 T _ccsrp_server_generate_public_key
00000000000726b9 T _ccsrp_server_start_authentication
000000000007271c T _ccsrp_server_verify_session
000000000003a89e t _ccsrp_sha_interleave_RFC2945
00000000000729fe T _ccsrp_test_calculations

*/

typedef ccdh_gp_t ccsrp_gp_t;
typedef ccdh_const_gp_t ccsrp_const_gp_t;

struct ccsrp_ctx {
    const struct ccdigest_info *digest;
    ccsrp_const_gp_t gp;
    /* Key size? */

    /* CCN fields... */

    /* K */
    /* M */
    /* public */
    /* private */
    /* ^ sizes are the same according to passwordserver_sasl, cyrus_sasl/plugins/srp.c, lines 2054 and 2063 */
};

typedef struct ccsrp_ctx *ccsrp_ctx_t;

/* the security framework gives me a lot of reference points */

/* mutableBytes == a regular pointer, bytes == constant pointer */

void ccsrp_ctx_init(ccsrp_ctx_t ctx, const struct ccdigest_info *digest, ccsrp_const_gp_t gp);

int ccsrp_generate_verifier(ccsrp_ctx_t ctx, const char *username,
                            size_t entropy_len, const void *entropy,
                            size_t salt_len, const void *salt,
                            void *out);

int ccsrp_generate_salt_and_verification(ccsrp_ctx_t ctx, const struct ccrng_state *rng,
                                         const char *username,
                                         size_t pass_len, const void *password,
                                         size_t salt_len, void *salt,
                                         void *verifier);

/* known SRP client funcs */
int ccsrp_client_start_authentication(ccsrp_ctx_t ctx, struct ccrng_state *rng, uint8_t *A);

int ccsrp_client_process_challenge(ccsrp_ctx_t ctx, const char *username,
                                   size_t password_len, const void *password,
                                   size_t salt_len, const void *salt,
                                   const void *b, void *m);

bool ccsrp_client_verify_session(ccsrp_ctx_t ctx, const void *data);


int csrp_server_start_authentication(ccsrp_ctx_t ctx, const struct ccrng_state *rng,
                                     const char *username,
                                     size_t salt_len, const void *salt,
                                     const void *verifier,
                                     const void *a,
                                     void *b);

/* known SRP server funcs */
int ccsrp_server_compute_session(ccsrp_ctx_t ctx, const char *idk,
                                 size_t salt_len, uint8_t *salt,
                                 uint8_t *server_key);

int ccsrp_server_generate_public_key(ccsrp_ctx_t ctx, struct ccrng_state *rng,
                                     void *verif, void *key);

int ccsrp_server_verify_session(ccsrp_ctx_t ctx, const void *m, void *hamk);


#endif /* _CORECRYPTO_CCSRP_H_ */
