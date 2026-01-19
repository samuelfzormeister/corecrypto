//
//  pd_crypto_digest_final.c
//  pdcrypto
//
//  Created by rafirafi on 3/17/16.
//  Copyright (c) 2016 rafirafi. All rights reserved.
//
//  le version adapted from xnu/osfmk/corecrypto/ccsha1/src/ccdigest_final_64be.c
//  be version copied from xnu, only function name was changed
//
//  xnu https://opensource.apple.com/source/xnu/xnu-2782.40.9
//  License https://opensource.apple.com/source/xnu/xnu-2782.40.9/APPLE_LICENSE

#include <stddef.h>

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest_priv.h>

void ccdigest_final_64le(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                         void *digest)
{
    unsigned char *dgst = digest;

    ccdigest_nbits(di, ctx) += ccdigest_num(di, ctx) * 8;
    ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0x80;

    /* If we don't have at least 8 bytes (for the length) left we need to add
     a second block. */
    if (ccdigest_num(di, ctx) > 64 - 8) {
        while (ccdigest_num(di, ctx) < 64) {
            ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
        }
        di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
        ccdigest_num(di, ctx) = 0;
    }

    /* pad upto block_size minus 8 with 0s */
    while (ccdigest_num(di, ctx) < 64 - 8) {
        ccdigest_data(di, ctx)[ccdigest_num(di, ctx)++] = 0;
    }

    CC_STORE64_LE(ccdigest_nbits(di, ctx), ccdigest_data(di, ctx) + 64 - 8);
    di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));

    /* copy output */
    for (unsigned int i = 0; i < di->output_size / 4; i++) {
        CC_STORE32_LE(ccdigest_state_u32(di, ctx)[i], dgst + (4 * i));
    }
}

#define ZORM_TAMPERING 1

#if ZORM_TAMPERING

void ccdigest_final_fn(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    di->final(di, ctx, digest);
}

#else

void ccdigest_final_fn(const struct ccdigest_info *di, ccdigest_ctx_t ctx, void *digest)
{
    // TODO: Is this the correct implementation?

#if BYTE_ORDER == BIG_ENDIAN
    ccdigest_final_64be(di, ctx, digest);
#elif BYTE_ORDER == LITTLE_ENDIAN
    ccdigest_final_64le(di, ctx, digest);
#else
    cc_abort("Unsupported byte order");
#endif
}

#endif
