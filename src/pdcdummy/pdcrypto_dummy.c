#include "pdcrypto_dummy.h"

#if KERNEL
#include <sys/systm.h>
#else
#include <stdio.h>
#endif

#include <corecrypto/ccdigest.h>

/*
 * to print what is used by xnu during boot
 */

const struct ccmode_xts pdcaes_xts_encrypt_dummy;
const struct ccmode_xts pdcaes_xts_decrypt_dummy;
const struct ccmode_gcm pdcaes_gcm_encrypt_dummy;
const struct ccmode_gcm pdcaes_gcm_decrypt_dummy;

void pdcpad_xts_decrypt_fn_dummy(const struct ccmode_xts *xts,
                                 ccxts_ctx *ctx,
                                 unsigned long nbytes,
                                 const void *in,
                                 void *out)
{
    printf("%s\n", __func__);
}

void pdcpad_xts_encrypt_fn_dummy(const struct ccmode_xts *xts,
                                 ccxts_ctx *ctx,
                                 unsigned long nbytes,
                                 const void *in,
                                 void *out)
{
    printf("%s\n", __func__);
}
