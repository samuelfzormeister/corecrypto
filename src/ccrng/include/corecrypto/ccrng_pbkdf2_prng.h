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

#ifndef _CORECRYPTO_CCRNG_PBKDF2_PRNG_H_
#define _CORECRYPTO_CCRNG_PBKDF2_PRNG_H_

#include <corecrypto/ccrng.h>

/* This doesn't even have to be compatible structure-layout wise. just has to work as intended. */
struct ccrng_pbkdf2_prng_state {
    CCRNG_STATE_COMMON

    size_t buffer_size;
    uint8_t buffer[4096];
};

int ccrng_pbkdf2_prng_init(struct ccrng_pbkdf2_prng_state *state,
                          size_t max_output,
                          size_t password_length, const void *password,
                          size_t salt_length, const void *salt,
                          size_t iterations);

/* Does this even have a specification? or does this just run a PBKDF2 HMAC operation? */

#endif /* _CORECRYPTO_CCRNG_PBKDF2_PRNG_H_ */
