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

#ifndef _CORECRYPTO_CCSPAKE_H_
#define _CORECRYPTO_CCSPAKE_H_

#include <stdint.h>
#include <corecrypto/ccec.h>

typedef struct ccspake_cp ccspake_cp_t;
typedef const ccspake_cp_t ccspake_const_cp_t;

ccspake_const_cp_t ccspake_cp_256_rfc(void);

size_t ccspake_sizeof_w(ccspake_const_cp_t cp);

int ccspake_reduce_w(ccspake_const_cp_t, size_t, void *, size_t, void *);

// #define CCSPAKE_HAS_REDUCE_W_RFC9383
// int ccspake_reduce_w_RFC9383(ccspake_const_cp_t, size_t, void *, size_t, void *);

#endif /* _CORECRYPTO_CCSPAKE_H_ */
