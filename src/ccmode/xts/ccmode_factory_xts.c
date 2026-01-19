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
#include <corecrypto/ccmode_internal.h>

void ccmode_factory_xts_decrypt(struct ccmode_xts *xts, const struct ccmode_ecb *ecb, const struct ccmode_ecb *ecb_encrypt)
{
    /* Fill in size parameters */
    xts->size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size(ecb->size);
    xts->block_size = ccecb_block_size(ecb);
    xts->tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(ecb->block_size);

    /* Populate function callbacks */
    xts->init = ccmode_xts_init;
    xts->key_sched = ccmode_xts_key_sched;
    xts->set_tweak = ccmode_xts_set_tweak;
    xts->xts = ccmode_xts_crypt;

    /* Populate the custom fields */
    xts->custom = ecb;
    xts->custom1 = ecb_encrypt;
}

void ccmode_factory_xts_encrypt(struct ccmode_xts *xts, const struct ccmode_ecb *ecb, const struct ccmode_ecb *ecb_encrypt)
{
    /* Fill in size parameters */
    xts->size = ccn_sizeof_size(sizeof(struct _ccmode_xts_key)) + 2 * ccn_sizeof_size(ecb->size);
    xts->block_size = ccecb_block_size(ecb);
    xts->tweak_size = ccn_sizeof_size(sizeof(struct _ccmode_xts_tweak)) + ccn_sizeof_size(ecb->block_size);

    /* Populate function callbacks */
    xts->init = ccmode_xts_init;
    xts->key_sched = ccmode_xts_key_sched;
    xts->set_tweak = ccmode_xts_set_tweak;
    xts->xts = ccmode_xts_crypt;

    /* Populate the custom fields */
    xts->custom = ecb;
    xts->custom1 = ecb_encrypt;
}
