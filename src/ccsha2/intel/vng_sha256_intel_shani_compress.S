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

#include <corecrypto/cc_config.h>

/* As far as I'm aware, no i386 CPU ever shipped with SHA-NI */
#if CCSHA2_VNG_INTEL && defined(__x86_64__)

/*
 * Intel SHA-NI extensions:
 *
 * sha256rnds2 <xmm reg 1>, <xmm reg 2>
 * This instruction implicitly uses the xmm0 register for the SHA round constants.
 *
 * eg: if this were round 1 and 2:
 * xmm0 {
 *    0x428a2f98 [31:0]
 *    0x71374491 [63:32]
 *    0x00000000 [95:64]
 *    0x00000000 [127:96]
 * }
 *
 * The SHA state fields A, B, E and F are in the first operand whilst the fields C, D, G and H are in the second operand.
 *
 */

/*
 * Is there really anything better to call this?
 */
.globl _vng_sha256_intel_shani_compress
.text align 90

/*
 * Incoming parameters:
 * - ccdigest_state_t state
 * - size_t nblocks
 * - const void *data
 */
_vng_sha256_intel_shani_compress:

    /* Follow the System-V ABI. Sorry Windows users, no accelerated assembly for you. */
    push %rbp

    /* WIP!!! */






#endif
