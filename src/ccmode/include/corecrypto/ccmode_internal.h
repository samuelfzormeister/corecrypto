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

#ifndef _CORECRYPTO_CCMODE_INTERNAL_H_
#define _CORECRYPTO_CCMODE_INTERNAL_H_

#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>

/* CBC key positioning */
#define CCMODE_CBC_KEY_ECB_CTX(cbckey) (ccecb_ctx *)&cbckey->u[0]
#define CCMODE_CBC_SCRATCH(ctx) (&ctx->u[ccn_sizeof_size(ctx->ecb->size)])

/* CFB key fields */
#define CCMODE_CFB_KEY_FEEDBACK(ctx) &ctx->u[0]
/* ^ rename to IV? */
#define CCMODE_CFB_KEY_PADDING(ctx) (&ctx->u[ccn_nof_size(ctx->ecb->block_size)])
#define CCMODE_CFB_KEY_ECB_CTX(ctx) (ccecb_ctx *)(&ctx->u[ccn_nof_size(ctx->ecb->block_size) * 2])

/* CFB key fields */
#define CCMODE_CFB8_KEY_FEEDBACK(ctx) &ctx->u[0]
/* ^ rename to IV? */
#define CCMODE_CFB8_KEY_PADDING(ctx) (ctx->u + ccn_sizeof_size(ctx->ecb->block_size))
#define CCMODE_CFB8_KEY_ECB_CTX(ctx) (ccecb_ctx *)(&ctx->u[2 * ccn_nof_size(ctx->ecb->block_size)])

#define CCMODE_CTR_KEY_COUNTER(ckey) &ckey->u[0]
#define CCMODE_CTR_KEY_PAD(ckey)     (&ckey->u[ccn_nof_size(ckey->ecb->block_size)])
#define CCMODE_CTR_KEY_ECB_CTX(ckey) (ccecb_ctx *)(&ckey->u[ccn_nof_size(ckey->ecb->block_size) * 2])

#define CCMODE_OFB_KEY_IV(okey)      &okey->u[0]
#define CCMODE_OFB_KEY_ECB_CTX(okey) (ccecb_ctx *)&okey->u[ccn_nof_size(okey->ecb->block_size)]

#define CCMODE_XTS_TWEAK_MAX_BLOCKS_PROCESSED 0x100000

#define CCMODE_XTS_KEY_ECB_CTX(xkey) (ccecb_ctx *)&xkey->u[0]
#define CCMODE_XTS_KEY_ECB_ENCRYPT_CTX(xkey) (ccecb_ctx *)(&xkey->u[ccn_nof_size(xkey->ecb->size)])

#define CCMODE_GCM_KEY(gkey) ((struct _ccmode_gcm_key *)gkey)
#define CCMODE_GCM_KEY_ECB_CTX(gkey) (ccecb_ctx *)&gkey->u[ccn_nof_size(gkey->ecb->block_size)]

/* this is exported to the symbol table, see cc_exports.txt */
void ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c);

/* also exported to the symbol table. */
void ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I);

#endif /* _CORECRYPTO_CCMODE_INTERNAL_H_ */
