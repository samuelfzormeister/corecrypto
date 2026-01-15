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

#include "gladman_aes_internal.h"

static int ccaes_gladman_cbc_encrypt_init(const struct ccmode_cbc *ecb, cccbc_ctx *ctx, size_t key_len, const void *key) {
    ccaes_gladman_encrypt_ctx *cx = (ccaes_gladman_encrypt_ctx *)ctx;
    cx->cbcEnable = 1;
    ccaes_gladman_encrypt_key(key, key_len, cx);
    return 0;
}

const struct ccmode_cbc ccaes_gladman_cbc_encrypt = {
    .block_size = CCAES_BLOCK_SIZE,
    .size = sizeof(ccaes_gladman_encrypt_ctx),
    
    .init = ccaes_gladman_cbc_encrypt_init,
    .cbc = ccaes_gladman_encrypt,
};
