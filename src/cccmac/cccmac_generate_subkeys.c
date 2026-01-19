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

#include <corecrypto/cc.h>
#include <corecrypto/cccmac_priv.h>
#include <corecrypto/ccmode.h>

const uint8_t constant_zero[CMAC_BLOCKSIZE] = { 0 };

/* recycled from older versions of CommonCrypto. */
void cc_leftshift_onebit(uint8_t *input, uint8_t *output)
{
    int i;
    uint8_t overflow = 0;

    for (i = 15; i >= 0; i--) {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = (input[i] & 0x80) ? 1 : 0;
    }
    return;
}

int cccmac_generate_subkeys(const struct ccmode_cbc *cbc, size_t key_nbytes, const void *key, uint8_t *key1, uint8_t *key2)
{
    const uint8_t iv[CMAC_BLOCKSIZE] = { 0 };
    uint8_t buf[CMAC_BLOCKSIZE] = { 0 };
    uint8_t tmp[CMAC_BLOCKSIZE] = { 0 };

    int ret = cccbc_one_shot(cbc, key_nbytes, key, iv, 1, buf, buf);
    if (ret) { return ret; }

    if ((buf[0] & 0x80) == 0) {
        cc_leftshift_onebit(buf, key1);
    } else {
        cc_leftshift_onebit(buf, tmp);
        cc_xor(CMAC_BLOCKSIZE, key1, tmp, constant_zero);
    }

    if ((key1[0] & 0x80) == 0) {
        cc_leftshift_onebit(key1, key2);
    } else {
        cc_leftshift_onebit(key1, tmp);
        cc_xor(CMAC_BLOCKSIZE, key2, tmp, constant_zero);
    }

    cc_clear(CMAC_BLOCKSIZE, buf);
    cc_clear(CMAC_BLOCKSIZE, tmp);

    return CCERR_OK;
}
