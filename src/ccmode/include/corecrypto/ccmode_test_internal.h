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

#ifndef _CORECRYPTO_CCMODE_TEST_INTERNAL_H_
#define _CORECRYPTO_CCMODE_TEST_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/cc_config.h>
#include <corecrypto/cctest_priv.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccmode_factory.h>

 /*
  * @group ccmode_test
  *
  * APIs for testing the ccmode series of functions.
  */

/*!
 * @struct ccmode_test_vector
 * A generic structure for a cipher test vector.
 *
 * @discussion
 * The IV field can be reused as a field for the tweak in XTS mode.
 */
struct ccmode_test_vector {
     uint32_t attrs;

     const char *key;
     size_t key_length;
     const char *iv;
     size_t iv_length;
     size_t text_length;
     const char *plaintext;
     const char *ciphertext;
     size_t add_length;
     const char *aad;
 };
struct ccmode_test_vector_info {
    const struct ccmode_test_vector *vectors;
    size_t nvectors;
};

struct _ccmode_test_ctx {
    const struct cctest_info *ti;
    const void *mode;
    const struct ccmode_test_vector_info *vi;
    cc_size block_size;
    cc_size ctx_size;
    cc_unit u[]; /* contains the relevant ctx */
};

#define CCMODE_TEST_CTX(ctx) ((struct _ccmode_test_ctx *)ctx)
#define CCMODE_TEST_VI(vi) ((struct ccmode_test_vector_info *)vi)
#define CCMODE_TEST_CTX_KEY(kind, ctx) (kind *) &ctx->u[0]
#define CCMODE_TEST_CTX_IV_SPACE(type, ctx) (type *)&ctx->u[ccn_nof_size(ctx->ctx_size)]
#define CCMODE_TEST_CTX_SCRATCH_SPACE(ctx) &ctx->u[ccn_nof_size(ctx->ctx_size + ctx->block_size)]

//
// Allow for space to conduct a test without allocating memory ourself.
//
#define CCMODE_TEST_CTX_SCRATCH_SIZE(mode) (mode->block_size * 28)

// cctest_info format:
// ccaes_IMPLNAME_TESTNAME_ti
#define CCMODE_TEST_FACTORY(cipher, mode, crypt, vectors, testname, altname, impl)         \
static struct cctest_info cc##cipher##_##impl##_##testname##_test;                  \
static struct ccmode_test_vector_info cc##cipher##_##impl##_##testname##_test_vi  \
    = { vectors , sizeof(vectors) / sizeof(struct ccmode_test_vector) };      \
                                                                          \
const struct cctest_info *cc##cipher##_##impl##_##testname##_ti() {          \
    const struct ccmode_##mode *ciph = &cc##cipher##_##impl##_mode;                      \
    ccmode_##mode##_##crypt##_test_factory(&cc##cipher##_##impl##_##testname##_test , ciph, altname , &cc##cipher##_##impl##_##testname##_test_vi ); \
    return &cc##cipher##_##impl##_##testname##_test;                                         \
}

#define CCMODE_CONSTRUCTED_TEST_FACTORY(cipher, mode, crypt, vectors, testname, altname, impl, ecb)         \
static struct cctest_info cc##cipher##_##impl##_##testname##_test;                  \
static struct ccmode_test_vector_info cc##cipher##_##impl##_##testname##_test_vi  \
    = { vectors , sizeof(vectors) / sizeof(struct ccmode_test_vector) };      \
                                                                          \
const struct cctest_info *cc##cipher##_##impl##_##testname##_ti() {          \
    static struct ccmode_##mode test_##cipher##_##impl##_mode; \
    ccmode_factory_##mode##_##crypt(&test_##cipher##_##impl##_mode , &cc##cipher##_##ecb##_mode); \
    const struct ccmode_##mode *ciph = &test_##cipher##_##impl##_mode;                      \
    ccmode_##mode##_##crypt##_test_factory(&cc##cipher##_##impl##_##testname##_test , ciph, altname , &cc##cipher##_##impl##_##testname##_test_vi ); \
    return &cc##cipher##_##impl##_##testname##_test;                                         \
}

#define CCMODE_ECB_TEST_FACTORY(cipher, crypt, vectors, altname, testname, impl) CCMODE_TEST_FACTORY(cipher, ecb, crypt, vectors, testname, altname, impl)
#define CCMODE_CBC_TEST_FACTORY(cipher, crypt, vectors, altname, testname, impl) CCMODE_TEST_FACTORY(cipher, cbc, crypt, vectors, testname, altname, impl)

void ccmode_ecb_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_ecb *mode, const char *name, struct ccmode_test_vector_info *vi);
void ccmode_ecb_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_ecb *mode, const char *name, struct ccmode_test_vector_info *vi);

void ccmode_cbc_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_cbc *mode, const char *name, struct ccmode_test_vector_info *vi);
void ccmode_cbc_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_cbc *mode, const char *name, struct ccmode_test_vector_info *vi);

void ccmode_ofb_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_ofb *mode, const char *name, struct ccmode_test_vector_info *vi);
void ccmode_ofb_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_ofb *mode, const char *name, struct ccmode_test_vector_info *vi);

void ccmode_cfb_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_cfb *mode, const char *name, struct ccmode_test_vector_info *vi);
void ccmode_cfb_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_cfb *mode, const char *name, struct ccmode_test_vector_info *vi);

void ccmode_cfb8_encrypt_test_factory(struct cctest_info *ti, const struct ccmode_cfb8 *mode, const char *name, struct ccmode_test_vector_info *vi);
void ccmode_cfb8_decrypt_test_factory(struct cctest_info *ti, const struct ccmode_cfb8 *mode, const char *name, struct ccmode_test_vector_info *vi);



#endif /* _CORECRYPTO_CCMODE_TEST_INTERNAL_H_ */
