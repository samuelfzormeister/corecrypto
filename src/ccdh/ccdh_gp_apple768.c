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

#include "ccdh_gp_decl.h"
#include <corecrypto/ccn.h>

/*
 contents:
     ffffffffffffffff
     ec14ad084d0a476d
     b7996e88529b1a37
     cbf608fb894c7297
     332ddefdaae97663
     bb1332a71044f868
     552a24e169ee3091
     66c505dbbeaf8ddc
     94619e6e28fccda3
     d4a0df17fccdb09a
     6575089ba8f8373b
     ffffffffffffffff
 recip:
     0000000000000001
     a75dfd8e105b6abf
     871a09bf23852823
     2799d0f179b00f8b
     b7244037537f5d74
     ccbd133c17c0af7c
     151a5caac45041bc
     079cbb5f84ac4937
     8fba0f4e762fdafc
     424cf52b4d38c371
     313354f47aedb1fe
     3eae79c4aea18b1c
     cbb4796e60cca4af
 */

ccdh_gp_decl_n(ccn_nof(768)) _ccdh_gp_apple768 = {
    .ccn_size = ccn_nof(768),
    .bitlen = 768,
    .p = {
        CCN64_C(FF, FF, FF, FF, FF, FF, FF, FF),
        CCN64_C(EC, 14, AD, 08, 4D, 0A, 47, 6D),
        CCN64_C(b7, 99, 6e, 88, 52, 9b, 1a, 37),
    },
};
