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

#include "ccsha2_ltc_internal.h"

const uint32_t ccsha256_initial_state[8] = {
    0x6A09E667UL, // A
    0xBB67AE85UL, // B
    0x3C6EF372UL, // C
    0xA54FF53AUL, // D
    0x510E527FUL, // E
    0x9B05688CUL, // F
    0x1F83D9ABUL, // G
    0x5BE0CD19UL, // H
};
