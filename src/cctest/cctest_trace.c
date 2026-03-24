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
#include <corecrypto/cctest_internal.h>

static const char *__subsystems[] = {
    "",

    "DIGEST",
    "CIPHER",

    "CHACHA20POLY1305",

    "PBKDF2",
    "SCRYPT",
    "HKDF",
    "NISTKDF",

    "CMAC",
    "HMAC",

    "WRAP",
    "DRBG",
};

static bool trace_enabled = false;

void cctest_enable_trace(bool enable)
{
    trace_enabled = enable;
}

void cctest_trace_fail(uint32_t subsystem, const char *name, uint32_t failed_vec)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s][%s]: FAIL %d\n", __subsystems[subsystem], name, failed_vec);
    }
}

void cctest_trace_fail_named(uint32_t subsystem, const char *name, const char *named)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s][%s]: FAIL %s\n", __subsystems[subsystem], name, named);
    }
}

void cctest_trace_general(uint32_t subsystem, const char *name, const char *msg)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s][%s]: %s\n", __subsystems[subsystem], name, msg);
    }
}


void cctest_trace_pass(uint32_t subsystem, const char *name, uint32_t failed_vec)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s][%s]: PASS %d\n", __subsystems[subsystem], name, failed_vec);
    }
}

void cctest_trace_pass_named(uint32_t subsystem, const char *name, const char *named)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s][%s]: PASS %s\n", __subsystems[subsystem], name, named);
    }
}

void cctest_trace_enter(uint32_t subsystem, const char *name, uint64_t abs)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s] conducting test, %s (stamp: %lld)\n", __subsystems[subsystem], name, abs);
    }
}

void cctest_trace_exit(uint32_t subsystem, const char *name, uint64_t abs)
{
    if (trace_enabled) {
        cc_printf("[CCTEST][%s] finishing test, %s (stamp: %lld)\n", __subsystems[subsystem], name, abs);
    }
}

