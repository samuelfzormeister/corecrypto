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


#include <corecrypto/cc_debug.h>
#include <corecrypto/cctest_priv.h>

#if CC_KERNEL
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)IOMalloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) IOFree(link, sizeof(struct _cctest_test_link))
#else
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)malloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) free(link)
#endif

//
// We build a "linked list" (I say that loosely, given there's no pointer to the last field)
// consisting of test info structures to sequentially run tests.
//
// There's probably not the best time between checking if a certain test's bit
// is enabled or not, but I don't think the impact would be too severe for quick
// testing on the fly.
//
struct _cctest_test_link {
    struct _cctest_test_link *next;
    const struct cctest_info *ti;
};

struct _cctest_test_link root;

int cctest_run(cctest_run_flags_t flags)
{
    struct _cctest_test_link *chain = &root;
    cc_printf("We have been asked to perform tests!\n");

#if CORECRYPTO_TEST
    if (flags & CCTEST_ENABLE_MD2) {
        chain->ti = ccmd2_ti();
        
        //
        // At this rate, I don't think we need CC_WORKSPACE because the only real thing
        // calling us is an extrnal tool. 
        //
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
    }

    if (flags & CCTEST_ENABLE_MD4) {
        chain->ti = ccmd4_ti();
        CCTEST_LINK_NEXT_ALLOC(chain);
        chain = chain->next;
    }
#endif
}
