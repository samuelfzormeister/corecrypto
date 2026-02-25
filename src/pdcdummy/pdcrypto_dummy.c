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

const struct ccmode_gcm pdcaes_gcm_encrypt_dummy;
const struct ccmode_gcm pdcaes_gcm_decrypt_dummy;

