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

#ifndef _CORECRYPTO_CCANSIKDF_H_
#define _CORECRYPTO_CCANSIKDF_H_

#include <corecrypto/ccdigest.h>

/*
 zormeister@Zormeisters-MacBook-Pro Sources % nm /usr/lib/system/libcorecrypto.dylib | grep ansikdf
    000000000004d5d8 T _ccansikdf_x963
    000000000004d4ee t _ccansikdf_x963_final
    000000000004d391 t _ccansikdf_x963_init
    000000000004d469 t _ccansikdf_x963_update
 */

//
// PUREDARWIN IMPLEMENTER'S NOTE:
// ANSI KDF is used for EC IES, alongside in CommonCrypto being re-exported through SPI and reused in Security.framework.
//

//
// SYMBOL-BASED ANALYSIS:
// They 100% split it up. Shared info is 100% in the update function, init using the key.
// That's how ChaCha20 works after all.
//

#define ccansikdf_x963_digest_entry_size(di) (cc_ceiling(sizeof(struct ccdigest_ctx) + ccdigest_di_size(di), 8) * 8)
#define ccansikdf_x963_digests_size(di, dk_len) ccansikdf_x963_digest_entry_size(di) * cc_ceiling(dk_len, di->output_size)
#define ccansikdf_x963_ctx_size(di, dk_len) sizeof(uint32_t) + (ccansikdf_x963_digests_size(di, dk_len))

#define ccansikdf_x963_ctx_decl(di, dk_len, name) \
   cc_ctx_decl(struct ccansikdf_x963_ctx, ccansikdf_x963_ctx_size(di, dk_len), name)

typedef struct ccansikdf_x963_ctx {
   uint32_t dk_len;
   CC_ALIGNED(8) struct ccdigest_ctx digests[];
} ccansikdf_x963_ctx_t;

int ccansikdf_x963(struct ccdigest_info *digest, size_t kdk_len, const void *kdk,
                   size_t sharedinfo_len, const void *sharedinfo,
                   size_t derived_len, void *dk);

//
// follows the same convention as cccmac for this function
//
int ccansikdf_x963_init(struct ccdigest_info *digest,
                        ccansikdf_x963_ctx_t *ctx,
                        size_t kdk_len, const void *kdk);

#endif /* _CORECRYPTO_CCANSIKDF_H_ */
