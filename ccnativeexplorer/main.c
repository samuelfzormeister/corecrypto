//
//  main.c
//  ccnativeexplorer
//
//  Created by Zormeister on 26/1/2025.
//

#include <corecrypto/cc.h>
#include <corecrypto/ccchacha20poly1305_priv.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccwrap.h>
#include <corecrypto/ccxof.h>
#include <stdio.h>
#include <stdlib.h>

void dump_dh_gp(ccdh_const_gp_t gp)
{
    const uint8_t *ptr = (const uint8_t *)gp;
    for (int i = 0; i < ccdh_gp_size(gp->n) * 5; i++) {
        printf("%02X ", ptr[i]);
    }
    printf("\n");

    printf("\n");
    printf("size: %zu\n", gp->n);
    printf("bits: %lld\n", gp->bitlen);
    printf("func: <%p>\n", gp->mulmod_prime);
    printf("prime: <%p>\n", ccdh_gp_prime(gp));
    printf("g: <%p>\n", ccdh_gp_g(gp));
    printf("l: <%lld>\n", ccdh_gp_l(gp));
    printf("order: <%p>\n", ccdh_gp_order(gp));
    printf("order bitlen: %zx\n", ccdh_gp_order_bitlen(gp));
    printf("gp size: %zd\n", ccdh_gp_size(gp->n));
}

void dump_xof(const struct ccxof_info *xof)
{
    printf("xof: <%p>", xof);
    const uint8_t *ptr = (const uint8_t *)xof;
    for (int i = 0; i < 64; i++) {
        printf("%02X ", ptr[i]);
    }
}

int main(int argc, const char *argv[])
{
    // insert code here...
    printf("Hello, World!\n");
    dump_dh_gp(ccdh_gp_apple768());
    dump_dh_gp(ccdh_gp_rfc2409group02());
    dump_dh_gp(ccdh_gp_rfc3526group05());
    dump_dh_gp(ccdh_gp_rfc3526group14());
    dump_dh_gp(ccdh_gp_rfc3526group15());
    dump_dh_gp(ccdh_gp_rfc3526group16());
    dump_dh_gp(ccdh_gp_rfc3526group17());
    dump_dh_gp(ccdh_gp_rfc3526group18());
    dump_dh_gp(ccdh_gp_rfc5114_MODP_1024_160());
    dump_dh_gp(ccdh_gp_rfc5114_MODP_2048_224());
    dump_dh_gp(ccdh_gp_rfc5114_MODP_2048_256());
    return 0;
}
