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
#include <corecrypto/cc_stub_diag.h>

// --- Use the backtrace dumping equivalent on Linux. --- //
#if CC_DARWIN || CC_LINUX

#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>

void cc_stub_log(const char *fn)
{
    void *local[10];
    cc_printf("corecrypto: %s invoked. aborting.\n", fn);
    cc_printf("backtrace for diagnostics:\n");
    // --- Hopefully this should diagnose what binary tried to use our stub? --- //
    backtrace_symbols_fd(local, 10, STDERR_FILENO);
    cc_printf("\n");
}

void cc_stub_log_abort(const char *fn)
{
    cc_stub_log(fn);
    abort();
}

#elif CC_KERNEL

#include <corecrypto/cc_priv.h>

void cc_stub_log(const char *fn)
{
    cc_printf("corecrypto:%s: some outside library is trying to use our darwinOS stubs.\n", fn);
}

void cc_stub_log_abort(const char *fn)
{
    cc_stub_log(fn);
    cc_printf("corecrypto:%s: according to the function called, this is illegal.\n", fn);
    cc_try_abort("stub.");
}


#else

// --- This is if anyone tries to call into Darwin stubs on Windows. --- //

#include <stdlib.h>

void cc_stub_log(const char *fn)
{
    cc_printf("corecrypto:%s: some outside library is trying to use our darwinOS stubs.\n", fn);
}

void cc_stub_log_abort(const char *fn)
{
    cc_stub_log(fn);
    cc_printf("corecrypto:%s: according to the function called, this is illegal.\n", fn);
    abort();
}

#endif
