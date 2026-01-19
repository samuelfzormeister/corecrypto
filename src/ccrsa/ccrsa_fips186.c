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

#include <corecrypto/ccn.h>
#include <corecrypto/ccrsa.h>

/* what key sizes do we support again? */
/* 1024, 2048, 3072, 4096 and 8192? */

int ccrsa_make_fips186_key(size_t nbits, const cc_size e_n, const cc_unit *e, /* Public exponent */
                           const cc_size xp1Len, const cc_unit *xp1,          /* This value is the value is the same as in B.3.6, step 4. */
                           const cc_size xp2Len, const cc_unit *xp2,          /* This value is the value is the same as in B.3.6, step 4. */
                           const cc_size xpLen, const cc_unit *xp,            /* This value is the RNGed value to generate the prime P */
                           const cc_size xq1Len, const cc_unit *xq1,          /* This value is the value is the same as in B.3.6, step 5. */
                           const cc_size xq2Len, const cc_unit *xq2,          /* This value is the value is the same as in B.3.6, step 5. */
                           const cc_size xqLen, const cc_unit *xq,            /* This value is the RNGed value to generate the prime Q */
                           ccrsa_full_ctx_t fk,                               /* our full key. How do we construct d if D */
                           cc_size *np, cc_unit *r_p,                         /* i assume this is the prime P */
                           cc_size *nq, cc_unit *r_q,                         /* i assume this is the prime Q */
                           cc_size *nm, cc_unit *r_m,                         /* i assume this is the modulus */
                           cc_size *nd, cc_unit *r_d)
{ /* i assume this is the private exponent d */
    /* FIPS186-4 states that a key length greater than 3072 is invalid. */
    /* Anywho, this means we have to construct the key from a FIPS186-4 generated set. */
    /* Fuck my life. */

    /* THAT FUNCTION SIGNATURE. FAR OUT. */
    return CCERR_OK;
}
