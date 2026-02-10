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

 /*
  * @group ccmode_test
  *
  * APIs for testing the ccmode series of functions.
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
     const char *aad;
     size_t add_length;
 };

struct ccmode_test_vector_info {
    const struct ccmode_test_vector *vectors;
    size_t nvectors;
};

struct _ccmode_test_ctx {
    const void *mode;
    const struct ccmode_test_vector_info *vi;
    size_t ctx_size;
    cc_unit u[]; /* contains the relevant ctx */
};

void ccmode_ecb_test_factory(struct cctest_info *ti, const struct ccmode_ecb *mode, const char *name, struct ccmode_test_vector_info *vi);

#endif /* _CORECRYPTO_CCMODE_TEST_INTERNAL_H_ */
