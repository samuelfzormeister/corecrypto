//
//  ccsha224_ltc_di.c
//  corecrypto
//
//  Created by Zormeister on 27/5/2025.
//

#include "ccsha2_ltc_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/ccsha2.h>

const struct ccdigest_info ccsha224_ltc_di = {
    .block_size = CCSHA256_BLOCK_SIZE,
    .output_size = CCSHA224_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,

    .final = ccdigest_final_64be,
    .compress = ccsha256_ltc_compress,

    .initial_state = ccsha224_initial_state,

    .oid = ccoid_sha224,
    .oid_size = ccoid_sha224_len,
};
