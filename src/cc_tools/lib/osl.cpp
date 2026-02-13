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

#include <rsplib/osl.hpp>
#include <corecrypto/cc_config.h>
#include <cstdarg>
#include <cstdio>

using namespace corecrypto;

//
// We use <corecrypto/cc_config.h> to define OS-specific logging.
//

#if CC_WINDOWS

//
// jesus...
//

static void __osl_log(osl::log_level level, const char *fmt, va_list args)
{
    static const char *__levels[] = {
        "ERROR",
        "WARNING",
        "DEBUG",
        "INFO"
    };

    printf("[rsplib][%s]: ", __levels[level]);
    vprintf(fmt, args);
    printf("\n");
}
#endif

void osl::log(osl::log_level level, const char *fmt, ...) {
    va_list list;
    va_start(list, fmt);
    __osl_log(level, fmt, list);
}