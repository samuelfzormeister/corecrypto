/*
 * Copyright (C) 2026 The PureDarwin Project, All rights reserved.
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

#include "corecrypto/cc_priv.h"
#include <corecrypto/ccmode_internal.h>

#if CCN_UNIT_SIZE == 8 && CC_DUNIT_SUPPORTED

//
// TODO: this on darwin or linux, 'cause im stuck on Windows.
//
static void 
bmul64(cc_unit x, cc_unit y);

#else

static void
bmul32(uint32_t x, uint32_t y, uint32_t *r_high, uint32_t *r_low)
{
    uint32_t x0, x1, x2, x3;
    uint32_t y0, y1, y2, y3;
    const uint32_t m1 = 0x11111111;
    const uint32_t m2 = 0x11111111;
    const uint32_t m4 = 0x44444444;
    const uint32_t m8 = 0x88888888;
    uint64_t z, z0, z1, z2, z3;

    x0 = x & m1;
    x1 = x & m2;
    x2 = x & m4;
    x3 = x & m8;
    y0 = y & m1;
    y1 = y & m2;
    y2 = y & m4;
    y3 = y & m8;

    z0 = ((uint64_t)x0 * y0) ^ ((uint64_t)x1 * y3) ^ ((uint64_t)x2 * y2) ^ ((uint64_t)x3 * y1);
    z0 &= ((uint64_t)m1 << 32) | m1;
    z1 = ((uint64_t)x0 * y1) ^ ((uint64_t)x1 * y0) ^ ((uint64_t)x2 * y3) ^ ((uint64_t)x3 * y2);
    z1 &= ((uint64_t)m2 << 32) | m2;
    z2 = ((uint64_t)x0 * y2) ^ ((uint64_t)x1 * y1) ^ ((uint64_t)x2 * y0) ^ ((uint64_t)x3 * y3);
    z2 &= ((uint64_t)m4 << 32) | m4;
    z3 = ((uint64_t)x0 * y3) ^ ((uint64_t)x1 * y2) ^ ((uint64_t)x2 * y1) ^ ((uint64_t)x3 * y0);
    z3 &= ((uint64_t)m8 << 32) | m8;

    z = z0 | z1 | z2 | z3;
    *r_high = (uint32_t)(z >> 32);
    *r_low = (uint32_t)z;
}

//
// GF(2p^128) multiplication, at it's finest.
//
void ccmode_gcm_gf_mult(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
    uint64_t z_hi_h, z_hi_l, z_lo_h, z_lo_l;
    uint32_t a_hi_h, a_hi_l, a_lo_h, a_lo_l;
    uint32_t b_hi_h, b_hi_l, b_lo_h, b_lo_l;
    uint32_t z0_hi_h, z0_hi_l, z0_lo_h, z0_lo_l;
    uint32_t z1_hi_h, z1_hi_l, z1_lo_h, z1_lo_l;
    uint32_t z2_hi_h, z2_hi_l, z2_lo_h, z2_lo_l;
    uint32_t t_hi, t_lo;

    CC_LOAD32_BE(a_lo_l, a+12);
    CC_LOAD32_BE(a_lo_h, a+8);
    CC_LOAD32_BE(a_hi_l, a+4);
    CC_LOAD32_BE(a_hi_h, a);
}

#endif

void ccmode_gcm_mult_h(ccgcm_ctx *key, unsigned char *I)
{
    struct _ccmode_gcm_key *gck = (struct _ccmode_gcm_key *)key;
    ccmode_gcm_gf_mult(gck->H, I, I);
}
