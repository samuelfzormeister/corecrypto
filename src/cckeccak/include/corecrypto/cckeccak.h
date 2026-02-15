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

#ifndef _CORECRYPTO_CCKECCAK_H_
#define _CORECRYPTO_CCKECCAK_H_

#include <corecrypto/cc.h>
#include <corecrypto/cc_config.h>

/* Grasping at straws here. */

/* 5 * 5 * 64 == 1600 */
struct cckeccak_state {
    uint64_t state[25];
};

typedef struct cckeccak_state *cckeccak_state_t;

int cckeccak_init_state(cckeccak_state_t state);

typedef int (*cckeccak_permutation)(cckeccak_state_t state, size_t length, const void *data);

/*
 000000000001e870 T _cckeccak_absorb_and_pad
 000000000001e805 T _cckeccak_absorb_blocks
 000000000001ea5c T _cckeccak_absorb_iovec
 000000000001e072 T _cckeccak_f1600_c
 000000000001ea38 T _cckeccak_get_permutation
 000000000001e7f3 T _cckeccak_init_state
 000000000001eda5 T _cckeccak_oneshot
 000000000001ecba T _cckeccak_oneshot_iovec
 000000000001e953 T _cckeccak_squeeze
 */

#endif /* _CORECRYPTO_CCKECCAK_H_ */
