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

#include "vng.h"
#include "../ccsha2_ltc_internal.h"
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/ccsha2.h>

const struct ccdigest_info ccsha224_vng_intel_shani_di = {
    .block_size = CCSHA256_BLOCK_SIZE,
    .output_size = CCSHA224_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,

    .final = ccdigest_final_64be,
    .compress = vng_sha256_intel_shani_compress,

    .initial_state = ccsha224_initial_state,

    .oid = ccoid_sha224,
    .oid_size = ccoid_sha224_len,
};

const struct ccdigest_info ccsha256_vng_intel_shani_di = {
    .block_size = CCSHA256_BLOCK_SIZE,
    .output_size = CCSHA256_OUTPUT_SIZE,
    .state_size = CCSHA256_STATE_SIZE,

    .final = ccdigest_final_64be,
    .compress = vng_sha256_intel_shani_compress,

    .initial_state = ccsha256_initial_state,

    .oid = ccoid_sha256,
    .oid_size = ccoid_sha256_len,
};
