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

#ifndef _CORECRYPTO_CCN_INTERNAL_H_
#define _CORECRYPTO_CCN_INTERNAL_H_

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn.h>

#if CCN_UNIT_SIZE == 8
#define ccn_clz cc_clz64
#else
#define ccn_clz cc_clz32

#if CC_UNIT_SIZE == 2
#define ccn_clz_extra 16
#elif CC_UNIT_SIZE == 1
#define ccn_clz_extra 24
#endif
#endif

//
// cc_unit helpers
//

CC_INLINE
cc_unit cc_unit_msb(cc_unit unit)
{
    return (unit >> (CCN_UNIT_BITS - 1));
}

CC_INLINE
cc_unit cc_unit_is_zero(cc_unit unit)
{
    //
    // if a unit is zero, the ~ operator will bitflip it such that
    // all bits will be set, and by subtracting 1 from zero it will
    // cause an integer underflow, giving us the same value.
    //
    return cc_unit_msb(~unit & (unit - 1));
}

CC_INLINE
cc_unit cc_unit_is_equal(cc_unit unit1, cc_unit unit2)
{
    //
    // as seen in cc_cmp_safe, XORing is the best option here.
    //
    return cc_unit_is_zero(unit1 ^ unit2);
}

/* ASM stuff... */
cc_unit ccn_add_asm(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t);
cc_unit ccn_sub_asm(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t);

#endif /* _CORECRYPTO_CCN_INTERNAL_H_ */
