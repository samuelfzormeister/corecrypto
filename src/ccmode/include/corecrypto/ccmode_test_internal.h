/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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
#include <corecrypto/ccmode.h>
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
#define CCMODE_TEST_CTX_SCRATCH_SPACE(ctx) &ctx->u[ccn_nof_size(ctx->ctx_size) + ccn_nof_size(ctx->ctx_size)]

//
// Allow for space to conduct a test without allocating memory ourself.
//
#define CCMODE_TEST_CTX_SCRATCH_SIZE(mode) 1000

// The AESVS MMT tests will at most have 160 blocks.
#define CCMODE_TEST_CTX_SCRATCH_SIZE_MMT(mode) 200

// cctest_info format:
// ccaes_IMPLNAME_TESTNAME_ti
#define CCMODE_TEST_FACTORY(cipher, mode, crypt, vectors, altname, impl)         \
static struct cctest_info cc##cipher##_##impl##_test;                  \
static struct ccmode_test_vector_info cc##cipher##_##impl##_test_vi  \
    = { vectors , sizeof(vectors) / sizeof(struct ccmode_test_vector) };      \
                                                                          \
const struct cctest_info *cc##cipher##_##impl##_ti() {          \
    const struct ccmode_##mode *ciph = &cc##cipher##_##impl##_mode;                      \
    ccmode_##mode##_##crypt##_test_factory(&cc##cipher##_##impl##_test , ciph, altname , &cc##cipher##_##impl##_test_vi ); \
    return &cc##cipher##_##impl##_test;                                         \
}

// this is for modes that are backed by the ECB implementation.
#define CCMODE_FACTORY_TEST_FACTORY(cipher, mode, crypt, vectors, altname)         \
static struct cctest_info cc##cipher##_##mode##_factory_##crypt##_test;                  \
static struct ccmode_test_vector_info cc##cipher##_##mode##_factory_##crypt##_test_vi  \
    = { vectors , sizeof(vectors) / sizeof(struct ccmode_test_vector) };      \
                                                                          \
const struct cctest_info *cc##cipher##_##mode##_factory_##crypt##_ti() {          \
    static struct ccmode_##mode test_##mode##_mode; \
    ccmode_factory_##mode##_##crypt(&test_##mode##_mode , cc##cipher##_ecb_##crypt##_mode()); \
    const struct ccmode_##mode *ciph = &test_##mode##_mode;                      \
    ccmode_##mode##_##crypt##_test_factory(&cc##cipher##_##mode##_factory_##crypt##_test , ciph, altname , &cc##cipher##_##mode##_factory_##crypt##_test_vi ); \
    return &cc##cipher##_##mode##_factory_##crypt##_test;                                         \
}

#define CCMODE_DEFAULT_TEST_FACTORY(cipher, mode, crypt, vectors, altname)         \
static struct cctest_info cc##cipher##_##mode##_##crypt##_default_test;                  \
static struct ccmode_test_vector_info cc##cipher##_##mode##_##crypt##_default_test_vi  \
    = { vectors , sizeof(vectors) / sizeof(struct ccmode_test_vector) };      \
                                                                          \
const struct cctest_info *cc##cipher##_##mode##_##crypt##_default_ti() {          \
    const struct ccmode_##mode *ciph = cc##cipher##_##mode##_##crypt##_mode();                      \
    ccmode_##mode##_##crypt##_test_factory(&cc##cipher##_##mode##_##crypt##_default_test , ciph, altname , &cc##cipher##_##mode##_##crypt##_default_test_vi ); \
    return &cc##cipher##_##mode##_##crypt##_default_test;                                         \
}


#define CCMODE_ECB_TEST_FACTORY(cipher, crypt, vectors, altname, impl) CCMODE_TEST_FACTORY(cipher, ecb, crypt, vectors, altname, impl)
#define CCMODE_CBC_TEST_FACTORY(cipher, crypt, vectors, altname, impl) CCMODE_TEST_FACTORY(cipher, cbc, crypt, vectors, altname, impl)
#define CCMODE_CFB_TEST_FACTORY(cipher, crypt, vectors, altname, impl) CCMODE_TEST_FACTORY(cipher, cfb, crypt, vectors, altname, impl)
#define CCMODE_CFB8_TEST_FACTORY(cipher, crypt, vectors, altname, impl) CCMODE_TEST_FACTORY(cipher, cfb8, crypt, vectors, altname, impl)
#define CCMODE_OFB_TEST_FACTORY(cipher, crypt, vectors, altname, impl) CCMODE_TEST_FACTORY(cipher, ofb, crypt, vectors, altname, impl)

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
