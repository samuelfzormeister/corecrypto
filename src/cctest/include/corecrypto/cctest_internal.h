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

#ifndef _CORECRYPTO_CCTEST_INTERNAL_H_
#define _CORECRYPTO_CCTEST_INTERNAL_H_

#include <corecrypto/cctest_priv.h>
#include <corecrypto/cc_memory.h>

//
// This declares all available tests to the subsystem.
//

extern const struct cctest_info *ccmd2_ti(void);
extern const struct cctest_info *ccmd4_ti(void);
extern const struct cctest_info *ccmd5_ltc_ti(void);

extern const struct cctest_info *ccrmd160_ti(void);

extern const struct cctest_info *ccsha1_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha1_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha224_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha224_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha256_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha256_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha384_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha384_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha512_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha512_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha512_224_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha512_224_ltc_shortmsg_ti(void);

extern const struct cctest_info *ccsha512_256_ltc_longmsg_ti(void);
extern const struct cctest_info *ccsha512_256_ltc_shortmsg_ti(void);

#include <corecrypto/ccaes_test.h>

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

#if CC_KERNEL
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)IOMalloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) IOFree(link, sizeof(struct _cctest_test_link))

#define cctest_malloc(size) IOMalloc(size)
#define cctest_free(ptr, size) IOFree(ptr, size)
#else
#define CCTEST_LINK_NEXT_ALLOC(link) link->next = (struct _cctest_test_link *)malloc(sizeof(struct _cctest_test_link))
#define CCTEST_LINK_FREE(link) free(link)

#define cctest_malloc(size) malloc(size)
#define cctest_free(ptr, size) free(ptr)
#endif

#define CCTEST_ADD_TEST(chain, info)                        \
    chain->ti = info;                                       \
    CCTEST_TRACE("Enabling test %s\n", info->name);    \
    CCTEST_LINK_NEXT_ALLOC(chain);                          \
    chain = chain->next;


enum {
    // --- Abstract layers. --- //
    CCTEST_SUBSYSTEM_DIGEST = 1,
    CCTEST_SUBSYSTEM_MODE,

    // --- AEAD modules (non-mode driven) --- //
    CCTEST_SUBSYSTEM_CHACHA20POLY1305,

    // --- Key Derivation Function modules --- //
    CCTEST_SUBSYSTEM_PBKDF2,
    CCTEST_SUBSYSTEM_SCRYPT,
    CCTEST_SUBSYSTEM_HKDF,
    CCTEST_SUBSYSTEM_NISTKDF,   // TODO: implement NIST KBKDFs.

    // --- MAC function modules --- //
    CCTEST_SUBSYSTEM_CMAC,
    CCTEST_SUBSYSTEM_HMAC,

    // --- Other modules --- //
    CCTEST_SUBSYSTEM_WRAP,
    CCTEST_SUBSYSTEM_DRBG,
};

void cctest_trace_enter(uint32_t subsystem, const char *name, uint64_t abs);
void cctest_trace_exit(uint32_t subsystem, const char *name, uint64_t abs);

void cctest_trace_fail(uint32_t subsystem, const char *name, uint32_t failed_vec);
void cctest_trace_general(uint32_t subsystem, const char *name, const char *msg);
void cctest_trace_pass(uint32_t subsystem, const char *name, uint32_t failed_vec);

void cctest_trace_fail_named(uint32_t subsystem, const char *name, const char *msg);
void cctest_trace_pass_named(uint32_t subsystem, const char *name, const char *msg);

#endif /* _CORECRYPTO_CCTEST_INTERNAL_H_ */
