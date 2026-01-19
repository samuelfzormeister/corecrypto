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

void ccmode_factory_cfb_encrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb)
{
    cfb->size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ecb)->block_size) + ccn_sizeof_size((ecb)->size);
    cfb->block_size = 1;
    cfb->init = ccmode_cfb_init;
    cfb->cfb = ccmode_cfb_encrypt;
    cfb->custom = ecb;
}

void ccmode_factory_cfb_decrypt(struct ccmode_cfb *cfb, const struct ccmode_ecb *ecb)
{
    cfb->size = ccn_sizeof_size(sizeof(struct _ccmode_cfb_key)) + 2 * ccn_sizeof_size((ecb)->block_size) + ccn_sizeof_size((ecb)->size);
    cfb->block_size = 1;
    cfb->init = ccmode_cfb_init;
    cfb->cfb = ccmode_cfb_decrypt;
    cfb->custom = ecb;
}
