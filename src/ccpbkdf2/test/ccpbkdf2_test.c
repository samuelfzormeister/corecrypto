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

#include <corecrypto/cc_absolute_time.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/cctest_internal.h>
#include <corecrypto/ccpbkdf2_test.h>

int ccpbkdf2_test_init(const struct cctest_info *info, cctest_ctx *ctx)
{
    struct ccpbkdf2_test_ctx *cx = (struct ccpbkdf2_test_ctx *)ctx;

    cx->ti = info;
    cx->di = (const struct ccdigest_info *)info->custom;
    cx->vi = (const struct ccpbkdf2_test_vector_info *)info->custom1;
    return 0;
}

int ccpbkdf2_test_run(cctest_ctx *ctx)
{
    struct ccpbkdf2_test_ctx *cx = (struct ccpbkdf2_test_ctx *)ctx;

    cctest_trace_enter(CCTEST_SUBSYSTEM_PBKDF2, cx->ti->name, cc_absolute_time());

    for (size_t vec = 0; vec < cx->vi->nvectors; vec++) {
        struct ccpbkdf2_test_vector *v = &cx->vi->vectors[vec];

        ccpbkdf2_hmac(cx->di, 
            v->password_len, v->password, 
            v->salt_len, v->salt, 
            v->iterations, 
            v->dk_len, cx->u);

        if (cc_cmp_safe(v->dk_len, cx->u, v->expected_dk) == 0) {
            cctest_trace_pass(CCTEST_SUBSYSTEM_PBKDF2, cx->ti->name, vec);
            cc_clear(v->dk_len, cx->u);
            continue;
        } else {
            cctest_trace_fail(CCTEST_SUBSYSTEM_PBKDF2, cx->ti->name, vec);
            
            uint8_t *dk = (uint8_t *)&cx->u[0];

            cc_printf("[CCTEST][PBKDF2][%s]: OUTPUT:\n", cx->ti->name);

            for (cc_size i = 0; i < v->dk_len; i++) {
                if ((i % 8) == 0) {
                    if (i > 0) {
                        cc_printf("\n");
                    }
                }
                cc_printf("%02x ", *dk);
                dk++;
            }
            
            cc_printf("\n");
            
            cc_printf("[CCTEST][PBKDF2][%s]: EXPECTED:\n", cx->ti->name);
            
            dk = (uint8_t *)v->expected_dk;
            
            for (cc_size i = 0; i < v->dk_len; i++) {
                if ((i % 8) == 0) {
                    if (i > 0) {
                        cc_printf("\n");
                    }
                }
                cc_printf("%02x ", *dk);
                dk++;
            }
            
            cc_printf("\n");
            
            cctest_trace_exit(CCTEST_SUBSYSTEM_PBKDF2, cx->ti->name, cc_absolute_time());
            
            return -1;
        }
    }

    cctest_trace_exit(CCTEST_SUBSYSTEM_PBKDF2, cx->ti->name, cc_absolute_time());
    return 0;
}

void ccpbkdf2_test_dump_state(CC_UNUSED cctest_ctx *)
{
    //
    // do nothing. we have no state.
    //
}

void ccpbkdf2_test_factory(struct cctest_info *ti, const struct ccdigest_info *di, const char *name, struct ccpbkdf2_test_vector_info *vi)
{
    ti->name = name;
    ti->custom = di;
    ti->custom1 = vi;

    ti->init = ccpbkdf2_test_init;
    ti->run = ccpbkdf2_test_run;
    ti->dump_state = ccpbkdf2_test_dump_state;

    ti->size = ccn_sizeof_size(sizeof(struct ccpbkdf2_test_ctx)) + (di->output_size * 2);
}
