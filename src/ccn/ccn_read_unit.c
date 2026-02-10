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

#include "corecrypto/cc_priv.h"
#include <corecrypto/ccn.h>

int ccn_read_unit(cc_size n, cc_unit *r, size_t data_nbytes, const uint8_t *data)
{
    /* if we need more N than we have, bail. */
    if (data_nbytes > ccn_sizeof_n(n)) {
        return -1;
    }

    /* corecrypto's constant ZPs have the primes in complete reverse */
    cc_try_abort("not yet");

    return 0;
}
