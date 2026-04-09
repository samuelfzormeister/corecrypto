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

#include <corecrypto/cc_memory.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccdigest_priv.h>


// --- https://www.rfc-editor.org/rfc/rfc2898 --- //
// --- https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf --- //

int ccpbkdf2_hmac(const struct ccdigest_info *di,
                  size_t passwordLen, const void *password,
                  size_t saltLen, const void *salt,
                  size_t iterations,
                  size_t dkLen, void *dk)
{
    size_t hLen = di->output_size;
    cchmac_di_decl(di, hmac);
    CC_WORKSPACE_STACK_DECL(state, di->state_size); // --- Use CC_WORKSPACE to enable Windows clients. --- //
    cc_unit *istate = state->start;

    // --- This is to match SP800-132's PBKDF2 spec. --- //
    if ((dkLen / di->output_size) > UINT32_MAX) {
        return CCERR_PARAMETER;
    }

    //
    // every invocation to HMAC uses the password as the key.
    //
    // thus, initialise a HMAC context and save the state to reduce
    // unnecessary computation.
    //
    cchmac_init(di, hmac, passwordLen, password);
    ccdigest_copy_state(di, istate, cchmac_istate(di, hmac));

    //
    // cchmac_final runs ccdigest_final on the internal cchmac_data
    // prior to finalising the MAC, which means we can use cchmac_data
    // to store our last MAC, which will then get compressed to generate
    // the new MAC.
    //
    for (uint32_t block = 1; dkLen > 0; block++) {
        uint32_t counter;
        size_t outLen = CC_MIN(dkLen, hLen);
        uint8_t *buffer = cchmac_data(di, hmac);

        CC_STORE32_BE(block, &counter);

        // --- Ensure that this is a fresh state. --- //
        ccdigest_copy_state(di, cchmac_istate(di, hmac), istate);
        cchmac_nbits(di, hmac) = di->block_size * 8;
        cchmac_num(di, hmac) = 0;

        cchmac_update(di, hmac, saltLen, salt);
        cchmac_update(di, hmac, sizeof(uint32_t), &counter);

        cchmac_final(di, hmac, buffer);

        cc_copy(outLen, dk, buffer);

        for (size_t i = 2; i <= iterations; i++) {
            // --- This resets the HMAC state to one where we can generate the new MAC. --- //
            ccdigest_copy_state(di, cchmac_istate(di, hmac), istate);
            cchmac_nbits(di, hmac) = di->block_size * 8;
            cchmac_num(di, hmac) = di->output_size;
            cchmac_final(di, hmac, buffer);
            cc_xor(outLen, dk, dk, buffer);
        }

        dk += outLen;
        dkLen -= outLen;
        outLen = CC_MIN(dkLen, hLen);
    }

    CC_WORKSPACE_STACK_FREE(state, di->state_size);

    return CCERR_OK;
}
