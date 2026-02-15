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

int ccansikdf_x963(struct ccdigest_info *digest, size_t kdk_len, const void *kdk,
                   size_t sharedinfo_len, const void *sharedinfo,
                   size_t derived_len, void *derived_key);

#endif /* _CORECRYPTO_CCANSIKDF_H_ */
