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

#include <corecrypto/cc_priv.h>
#include <corecrypto/cckeccak.h>

#define LANE(n) state->lanes[n]

/*
 * There's a lot of pointless integer arithmatic in many versions of F1600.
 *
 * I get it but I don't.
 *
 * Derived from:
 * https://github.com/libtom/libtomcrypt/blob/63af5f6dc15a686ff2099676e0fd02550ec87659/src/hashes/sha3.c
 *
 * A lot of the modulo invocations can be calculated and optimised ahead of time, because we expect a total of 24 rounds.
 */
static void cckeccak_f1600_round(cckeccak_state_t state, uint64_t rcon)
{
    uint64_t work0, work1, work2, work3, work4, tmp, tmp2;

    /* theta function begins here */

    /*
     for (i = 0; i < 5; i++) {
        bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
     }
     */
    work0 = LANE(0) ^ LANE(5) ^ LANE(10) ^ LANE(15) ^ LANE(20);
    work1 = LANE(1) ^ LANE(6) ^ LANE(11) ^ LANE(16) ^ LANE(21);
    work2 = LANE(2) ^ LANE(7) ^ LANE(12) ^ LANE(17) ^ LANE(22);
    work3 = LANE(3) ^ LANE(8) ^ LANE(13) ^ LANE(18) ^ LANE(23);
    work4 = LANE(4) ^ LANE(9) ^ LANE(14) ^ LANE(19) ^ LANE(24);

    /*
     for (i = 0; i < 5; i++) {
        t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
        for (j = 0; j < 25; j += 5) {
           s[j + i] ^= t;
        }
      }
     */
    tmp = work4 ^ CC_ROL64(work1, 1);
    LANE(0) ^= tmp;
    LANE(5) ^= tmp;
    LANE(10) ^= tmp;
    LANE(15) ^= tmp;
    LANE(20) ^= tmp;
    tmp = work0 ^ CC_ROL64(work2, 1);
    LANE(1) ^= tmp;
    LANE(6) ^= tmp;
    LANE(11) ^= tmp;
    LANE(16) ^= tmp;
    LANE(21) ^= tmp;
    tmp = work1 ^ CC_ROL64(work3, 1);
    LANE(2) ^= tmp;
    LANE(7) ^= tmp;
    LANE(12) ^= tmp;
    LANE(17) ^= tmp;
    LANE(22) ^= tmp;
    tmp = work2 ^ CC_ROL64(work4, 1);
    LANE(3) ^= tmp;
    LANE(8) ^= tmp;
    LANE(13) ^= tmp;
    LANE(18) ^= tmp;
    LANE(23) ^= tmp;
    tmp = work3 ^ CC_ROL64(work0, 1);
    LANE(4) ^= tmp;
    LANE(9) ^= tmp;
    LANE(14) ^= tmp;
    LANE(19) ^= tmp;
    LANE(24) ^= tmp;

    /* theta function end */

    /* rho & pi */

    /*
     static const unsigned s_keccakf_rotc[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
     };

     static const unsigned s_keccakf_piln[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
     };

      t = s[1];
      for(i = 0; i < 24; i++) {
         j = s_keccakf_piln[i];
         bc[0] = s[j];
         s[j] = ROL64(t, s_keccakf_rotc[i]);
         t = bc[0];
      }
     */
   tmp = LANE(1);
   tmp2 = LANE(10);
   LANE(10) = CC_ROL64(tmp, 1);
   tmp2 = LANE(10);
   LANE(10) = CC_ROL64(tmp, 1);
}

#undef LANE

static uint64_t cckeccak_round_constants[25] = {

};

void cckeccak_f1600_c(cckeccak_state_t state)
{

}
