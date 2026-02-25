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

#ifndef _CORECRYPTO_CCTEST_PRIV_H_
#define _CORECRYPTO_CCTEST_PRIV_H_

#include <stdbool.h>
#include <corecrypto/cc.h>

/*
 * POST will use the cctest framework, however the exhaustive list will be disabled.
 */
#if CORECRYPTO_TEST == 0
#define CCTEST_FULL_TESTS 1
#else
#define CCTEST_FULL_TESTS 0
#endif

/*!
 * @group cctest
 *
 * The replacement for the old cctest binary, enabling library-level regression testing at runtime.
 *
 * In the future, this subsystem can likely enable a FIPS Pre-Operations Self Test
 *
 * See these links for more details:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Module-Validation-Program/documents/fips140-2/FIPS1402IG.pdf
 * https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf\
 *
 * The full testing dylib should be placed at /usr/local/lib/libcorecrypto_test.dylib
 */

/*
 * @group Attributes
 * Attributes of the test vector, indicating whether or not the test is expected to fail.
 */
enum {
    CCTEST_ATTRS_NONE = 0,

    CCTEST_ATTR_EXPECTEDFAIL = (1 << 0),
};

enum {
    CCTEST_ENABLE_MD2 = (1 << 0),
    CCTEST_ENABLE_MD4 = (1 << 1),
    CCTEST_ENABLE_AES = (1 << 2),
    CCTEST_ENABLE_MD5 = (1 << 3),
    CCTEST_ENABLE_RIPEMD = (1 << 4),
    CCTEST_ENABLE_SHA1 = (1 << 5),
    CCTEST_ENABLE_SHA2 = (1 << 6),

    CCTEST_ENABLE_ALL = 0x0FFFFFFF,
};

cc_aligned_struct(16) cctest_ctx;

#define cctest_ctx_decl(size, name) cc_ctx_decl(cctest_ctx, size, name)
#define cctest_ctx_clear(size, name) cc_clear(size, name)

struct cctest_info {
    const char *name;
    size_t size; /* Size of the mode_c */
    int (*init)(const struct cctest_info *info, cctest_ctx *ctx);
    int (*run)(cctest_ctx *ctx);
    void (*dump_state)(cctest_ctx *ctx);

    /* 
     * These fields help give additional context to layers that may need it
     * See ccdigest_test_internal.h and ccmode_test_internal.h
     */
    const void *custom;
    const void *custom1;
};

CC_INLINE int cctest_init(const struct cctest_info *ti, cctest_ctx *ctx) {
    return ti->init(ti, ctx);
}

CC_INLINE int cctest_run(const struct cctest_info *ti, cctest_ctx *ctx) {
    return ti->run(ctx);
}

CC_INLINE void cctest_dump_state(const struct cctest_info *ti, cctest_ctx *ctx)
{
    ti->dump_state(ctx);
}

/* APIs */
int cctest_conduct_tests(uint32_t);

//
// TODO: This should be integrated with a Power-On Self Test at somepoint, or return CCPOST codes.
//
// This is primarily an issue because we need to be able to identify WHY we failed.
//

void cctest_enable_trace(bool enable);

typedef enum {
    CCTEST_MODE_ECB = 1,
    CCTEST_MODE_CBC,
    CCTEST_MODE_CFB,
    CCTEST_MODE_CFB8,
    CCTEST_MODE_OFB,
    CCTEST_MODE_CTR,
    CCTEST_MODE_XTS,
} cctest_mode_t;

int ccaes_test_gfsbox(cctest_mode_t);
int ccaes_test_varkey(cctest_mode_t);

#endif /* _CORECRYPTO_CCTEST_PRIV_H_ */
