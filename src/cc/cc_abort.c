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

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_priv.h>

//
// cc_abort
//

/* Should I define this as POSIX or STDC? tbh who cares. */
#define CC_POSIX (CC_LINUX || CC_OSX)

#if CC_POSIX

#include <stdio.h>
#include <stdlib.h>

void cc_abort(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    abort();
}

#elif CC_KERNEL

#include <kern/debug.h>

void cc_abort(const char *msg)
{
    panic("%s", msg);
}

#endif
