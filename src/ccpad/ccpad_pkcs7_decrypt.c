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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccpad.h>

size_t ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv, size_t nbytes, const void *in, void *out)
{
    /* hopefully nbytes is a multiple of the block size, otherwise that might be a problem ngl. */
    size_t block_size = cccbc_block_size(cbc);
    size_t blocks = nbytes / block_size;

    /* run decryption */
    cccbc_update(cbc, ctx, iv, blocks, in, out);

    /* and return the size of the unpadded data. */
    return nbytes - ccpad_pkcs7_decode(block_size, out + (nbytes - block_size));
}
