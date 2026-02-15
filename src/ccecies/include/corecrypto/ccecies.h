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

#ifndef _CORECRYPTO_CCECIES_H_
#define _CORECRYPTO_CCECIES_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccmode.h>

struct ccecies_gcm;

#define ECIES_EPH_PUBKEY_IN_SHAREDINFO1 0x1
#define ECIES_EXPORT_PUB_STANDARD 0x2
#define ECIES_LEGACY_IV 0x4

void ccecies_decrypt_gcm_setup(struct ccecies_gcm *ecies,
                               const struct ccdigest_info *di,
                               const struct ccmode_gcm *gcm,
                               size_t key_size, size_t unk,
                               uint32_t options);

void ccecies_encrypt_gcm_setup(struct ccecies_gcm *ecies,
                               const struct ccdigest_info *di,
                               const struct ccmode_gcm *gcm,
                               size_t key_size, size_t unk,
                               uint32_t options);

#endif /* _CORECRYPTO_CCECIES_H_ */
