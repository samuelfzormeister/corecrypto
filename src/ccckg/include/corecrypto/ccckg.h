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

#ifndef _CORECRYPTO_CCCKG_H_
#define _CORECRYPTO_CCCKG_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>

// --- This is a stub header, I'm unsure as to what the protocol actually is. --- //

/*
 * "collaborative key generation"
 *
 * https://github.com/apple-oss-distributions/CommonCrypto/blob/a0ac082c/include/Private/CommonCollabKeyGen.h#L18-L37
 */

struct ccckg_ctx;

typedef struct ccckg_ctx ccckg_ctx_t;

size_t ccckg_sizeof_commitment(ccec_const_cp_t cp, const struct ccdigest_info *di);

size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di);

size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di);

void ccckg_init(ccckg_ctx_t *ctx, 
               ccec_const_cp_t cp, 
               const struct ccdigest_info *di, 
               const struct ccrng_state *rng);

#endif /* _CORECRYPTO_CCCKG_H_ */
