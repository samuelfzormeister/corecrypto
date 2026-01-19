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

/* These functions are essentially act as wrappers so every implementation doesn't need to repeat the same code. */

void ccmode_factory_cbc_encrypt(struct ccmode_cbc *cbc, const struct ccmode_ecb *ecb)
{
    /* construct a cbc mode from an ecb mode. */

    cbc->block_size = ecb->block_size;                                                                                           /* equal block sizes */
    cbc->custom = ecb;                                                                                                           /* this is how we get the selected ecb mode to the context in init */
    cbc->size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size(ecb->block_size) + ccn_sizeof_size(ecb->size); /* take into account that the context size could be different across */

    cbc->init = ccmode_cbc_init;
    cbc->cbc = ccmode_cbc_encrypt;
}

void ccmode_factory_cbc_decrypt(struct ccmode_cbc *cbc, const struct ccmode_ecb *ecb)
{
    /* construct a cbc mode from an ecb mode. */

    cbc->block_size = ecb->block_size;                                                                                           /* equal block sizes */
    cbc->custom = ecb;                                                                                                           /* this is how we get the selected ecb mode to the context in init */
    cbc->size = ccn_sizeof_size(sizeof(struct _ccmode_cbc_key)) + ccn_sizeof_size(ecb->block_size) + ccn_sizeof_size(ecb->size); /* take into account that the context size could be different across */

    cbc->init = ccmode_cbc_init;
    cbc->cbc = ccmode_cbc_decrypt;
}
