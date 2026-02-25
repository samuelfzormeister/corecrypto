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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccpad.h>

size_t ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, 
                          cccbc_iv *iv, size_t nbytes, 
                          const void *in, void *out)
{
    cc_size block_size = cccbc_block_size(cbc);
    cc_size nblocks = nbytes / block_size;
    cc_size bytes_nopad = nblocks * block_size;
    cc_size leftover = nbytes - bytes_nopad;
    cc_size bytes;
    uint8_t pad[16 * 2];

    if (leftover) {
        cccbc_update(cbc, ctx, iv, (nblocks - 1), in, out);

        // Pm-1 && Cm-1
        in += (bytes_nopad - block_size);
        out += (bytes_nopad - block_size);

        cc_clear(block_size * 2, pad);
        cc_copy(leftover + block_size, pad, in);
        // encrypt the last two blocks
        cccbc_update(cbc, ctx, iv, 2, pad, pad);

        // copy cm-1
        cc_copy(block_size - leftover, out, pad);

        // copy cm
        cc_copy(block_size, (out + leftover), (pad + block_size));

        cc_clear(block_size * 2, pad);
    } else {
        cccbc_update(cbc, ctx, iv, nblocks, in, out);
    }

    return nbytes;
}
