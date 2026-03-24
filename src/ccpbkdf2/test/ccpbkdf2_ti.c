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

#include <corecrypto/cctest_internal.h>
#include <corecrypto/ccpbkdf2_test.h>

extern int ccpbkdf2_test_init(const struct cctest_info *info, cctest_ctx *ctx);
extern int ccpbkdf2_test_run(cctest_ctx *ctx);
extern void ccpbkdf2_test_dump_state(cctest_ctx *ctx);
extern void ccpbkdf2_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccpbkdf2_test_vector_info *vi);

static struct ccpbkdf2_test_vector rfc7914_vectors[] = {
#include "vectors/rfc7914.inc"
};

static struct ccpbkdf2_test_vector_info rfc7914_vi = {
    .vectors = rfc7914_vectors,
    sizeof(rfc7914_vectors) / sizeof(struct ccpbkdf2_test_vector)
};

const struct cctest_info *ccpbkdf2_rfc7914_ti(void)
{
    static struct cctest_info my_info;
    ccpbkdf2_test_factory(&my_info, ccsha256_di(), "RFC7914", &rfc7914_vi);
    return &my_info;
}
