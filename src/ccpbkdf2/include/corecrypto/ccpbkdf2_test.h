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

#ifndef _CORECRYPTO_CCPBKDF2_TEST_H_
#define _CORECRYPTO_CCPBKDF2_TEST_H_

#include <corecrypto/cctest_priv.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

const struct cctest_info *ccpbkdf2_rfc7914_ti(void);
const struct cctest_info *ccpbkdf2_rfc6070_ti(void);

struct ccpbkdf2_test_vector {
    uint32_t attrs;

    size_t iterations;
    const char *password;
    size_t password_len;
    const char *salt;
    size_t salt_len;
    const char *expected_dk;
    size_t dk_len;
};

struct ccpbkdf2_test_vector_info {
    struct ccpbkdf2_test_vector *vectors;
    size_t nvectors;
};

struct ccpbkdf2_test_ctx {
    const struct cctest_info *ti;
    const struct ccdigest_info *di;
    const struct ccpbkdf2_test_vector_info *vi;

    cc_unit u[];
};

#define CCPBKDF2_TEST_CTX_MAX_DKLEN 64

#endif /* _CORECRYPTO_CCPBKDF2_TEST_H_ */
