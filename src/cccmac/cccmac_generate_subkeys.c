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

#include <corecrypto/cc.h>
#include <corecrypto/cccmac_priv.h>
#include <corecrypto/ccmode.h>

/* recycled from older versions of CommonCrypto. */
void cc_leftshift_onebit(uint8_t *input, uint8_t *output)
{
    int i;
    uint8_t overflow = 0;

    for (i = 15; i >= 0; i--) {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = input[i] >> 7;   // why bitmask and check when you can just have a value by shifting.
    }
    return;
}

/* another internal function... */
void cccmac_sl_test_xor(uint8_t *out, uint8_t *in)
{
    uint8_t tmp = 0;
    cc_leftshift_onebit(in, out);

    // officially constant-time - i believe
    tmp = out[0];
    tmp = (tmp & 0x80);         // get bit 7 status
    tmp = (0 - tmp) & 0x87;     // if the bit is set, this will underflow giving us the value needed
    out[15] ^= tmp;
}

int cccmac_generate_subkeys(const struct ccmode_cbc *cbc, size_t key_nbytes, const void *key, uint8_t *key1, uint8_t *key2)
{
    const uint8_t iv[CMAC_BLOCKSIZE] = { 0 };
    uint8_t buf[CMAC_BLOCKSIZE] = { 0 };

    int ret = cccbc_one_shot(cbc, key_nbytes, key, iv, 1, buf, buf);
    if (ret) { return ret; }

    cccmac_sl_test_xor(key1, buf);
    cccmac_sl_test_xor(key2, key1);

    cc_clear(CMAC_BLOCKSIZE, buf);

    return CCERR_OK;
}
