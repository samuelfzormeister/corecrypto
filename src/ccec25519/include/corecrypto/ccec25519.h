/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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

#ifndef _CORECRYPTO_CCEC25519_H_
#define _CORECRYPTO_CCEC25519_H_

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>

/*
 * WebKit says that since Sunburst (macOS Sonoma), these func sigs have been INT value.
 *
 * TODO: corecrypto SDK checks?
 *
 * SDK's <libkern/version.h> should provide Darwin version.
 */

typedef uint8_t ccec25519key[16];
typedef ccec25519key ccec25519secretkey;
typedef ccec25519key ccec25519pubkey;
typedef ccec25519key ccec25519base;

typedef uint8_t ccec25519signature[64];

void cccurve25519(ccec25519key pub, const ccec25519secretkey secret, const ccec25519base basepoint);

CC_INLINE
void cccurve25519_make_priv(struct ccrng_state *rng, ccec25519secretkey priv)
{
    ccrng_generate(rng, 32, priv);
    priv[0] &= 248;
    priv[31] &= 128;
    priv[31] |= 64;
}

CC_INLINE
void cccurve25519_make_pub(ccec25519pubkey pub, const ccec25519secretkey sk)
{
    cccurve25519(pub, sk, NULL);
}

CC_INLINE
void cccurve25519_make_key_pair(struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk)
{
    cccurve25519_make_priv(rng, sk);
    cccurve25519_make_pub(pk, sk);
}

int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pub, const ccec25519secretkey sk);

void cced25519_make_key_pair(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk);

void cced25519_sign(const struct ccdigest_info *, ccec25519signature, size_t len, const void *msg, const ccec25519pubkey pk, const ccec25519secretkey sk);

int cced25519_verify(const struct ccdigest_info *di,
                     size_t len, const void *msg,
                     const ccec25519signature sig,
                     const ccec25519pubkey pub);

#endif /* _CORECRYPTO_CCEC25519_H_ */
