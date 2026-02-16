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

#ifndef _CORECRYPTO_CCDIGEST_TEST_INTERNAL_H_
#define _CORECRYPTO_CCDIGEST_TEST_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/cc_config.h>
#include <corecrypto/cctest_priv.h>
#include <corecrypto/ccn.h>

/*
 * @group ccdigest_test
 *
 * APIs for testing the ccmode series of functions.
 */

typedef struct ccdigest_test_vector {
    uint32_t attrs;

    const char *message;
    size_t msg_len;
    const char *expected_digest;
} ccdigest_test_vector;

struct ccdigest_test_vector_info {
    const ccdigest_test_vector *vectors;
    size_t nvectors;
};

struct _ccdigest_test_ctx {
    const struct cctest_info *ti;
    const struct ccdigest_info *di;
    const struct ccdigest_test_vector_info *vi;
    size_t ctx_size;
    cc_unit u[]; /* contains the relevant ccdigest_ctx */
};

#define CCDIGEST_TEST_CTX(ctx) ((struct _ccdigest_test_ctx *)ctx)
#define CCDIGEST_TEST_VI(vi) ((struct ccdigest_test_vector_info *)vi)
#define CCDIGEST_TEST_CTX_DIGEST_CTX(ctx) (ccdigest_ctx_t)&ctx->u
#define CCDIGEST_TEST_CTX_SCRATCH_SPACE(ctx) &ctx->u[ccn_nof_size(ctx->ctx_size)];

#define CCDIGEST_TEST_FACTORY(name, vectors, altname)                     \
static struct cctest_info ccdigest_test_##name;                           \
static struct ccdigest_test_vector_info ccdigest_test_##name##_vi         \
    = { vectors , sizeof(vectors) / sizeof(ccdigest_test_vector) };      \
                                                                          \
const struct cctest_info *cc##name##_ti() {                               \
    const struct ccdigest_info *di = &cc##name##_di;                      \
    ccdigest_test_factory(&ccdigest_test_##name , di, altname , &ccdigest_test_##name##_vi ); \
    return &ccdigest_test_##name;                                         \
}

#define CCDIGEST_TEST_NAMED_FACTORY(name, impl, vectors, altname)                     \
static struct cctest_info ccdigest_test_##impl##_##name;                           \
static struct ccdigest_test_vector_info ccdigest_test_##impl##_##name##_vi         \
    = { vectors , sizeof(vectors) / sizeof(ccdigest_test_vector) };      \
                                                                          \
const struct cctest_info *cc##impl##_##name##_ti() {                               \
    const struct ccdigest_info *di = &cc##impl##_di;                      \
    ccdigest_test_factory(&ccdigest_test_##impl##_##name , di, altname , &ccdigest_test_##impl##_##name##_vi ); \
    return &ccdigest_test_##impl##_##name;                                         \
}

void ccdigest_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccdigest_test_vector_info *vi);

int ccdigest_test_init(const struct cctest_info *info, cctest_ctx *ctx);
int ccdigest_test_run(cctest_ctx *ctx);

#endif /* _CORECRYPTO_CCDIGEST_TEST_INTERNAL_H_ */
