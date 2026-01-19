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

#include "ccrc4_eay_internal.h"
#include <corecrypto/cc_error.h>
#include <corecrypto/ccrc4.h>

static void ccrc4_eay_init(ccrc4_ctx *ctx, size_t key_len, const void *key)
{
    eay_RC4_set_key((RC4_KEY *)ctx, key_len, key);
}

static void ccrc4_eay_crypt(ccrc4_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    eay_RC4((RC4_KEY *)ctx, nbytes, in, out);
}

const struct ccrc4_info ccrc4_eay = {
    .size = ccn_sizeof_size(sizeof(RC4_KEY)),
    .init = ccrc4_eay_init,
    .crypt = ccrc4_eay_crypt,
};
