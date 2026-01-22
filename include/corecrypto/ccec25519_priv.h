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

#ifndef _CORECRYPTO_CCEC25519_PRIV_H_
#define _CORECRYPTO_CCEC25519_PRIV_H_

#include <corecrypto/ccec25519.h>

/*
 * Are the X25519 functions private?
 *
 * What functions live in <corecrypto/ccec25519_priv.h>???
 */

void cccurve25519(ccec25519key out, const ccec25519secretkey secret, const ccec25519base pub);

void cccurve25519_make_priv(struct ccrng_state *rng, ccec25519secretkey sk);
void cccurve25519_make_pub(ccec25519pubkey pub, const ccec25519secretkey sk);
void cccurve25519_make_key_pair(struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk);

#endif /* _CORECRYPTO_CCEC25519_PRIV_H_ */
