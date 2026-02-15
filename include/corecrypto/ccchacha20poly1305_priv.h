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

#ifndef _CORECRYPTO_CCCHACHA20POLY1305_PRIV_H_
#define _CORECRYPTO_CCCHACHA20POLY1305_PRIV_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccchacha20poly1305.h>

/*!
 * @function ccchacha20_init
 * @abstract Initialize a ChaCha20 context.
 *
 * @param      ctx        The ChaCha20 context
 * @param      key        Secret key
 */
int ccchacha20_init(ccchacha20_ctx *ctx, const void *key);

/*!
 * @function ccchacha20_setcounter
 * @abstract Set the counter of a ChaCha20 context.
 *
 * @param      ctx        The ChaCha20 context
 * @param      counter    The new counter value
 */
int ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter);

/*!
 * @function ccchacha20_setnonce
 * @abstract Set the nonce of a ChaCha20 context.
 *
 * @param      ctx        The ChaCha20 context
 * @param      nonce      The new nonce
 */
int ccchacha20_setnonce(ccchacha20_ctx *ctx, const void *nonce);

/*!
 * @function ccchacha20_update
 * @abstract Encrypt/Decrypt data using ChaCha20.
 *
 * @param      ctx        The ChaCha20 context
 * @param      nbytes     Number of bytes to process
 * @param      in         Data to process
 * @param      out        Processed data
 */
int ccchacha20_update(ccchacha20_ctx *ctx, size_t nbytes, const void *in, void *out);

/*!
 * @function ccchacha20_final
 * @abstract Finalize a ChaCha20 context.
 *
 * @param      ctx        The ChaCha20 context
 */
int ccchacha20_final(ccchacha20_ctx *ctx);

/*!
 * @function ccchacha20_reset
 * @abstract Reset a ChaCha20 context.
 *
 * @param      ctx        The ChaCha20 context
 */
int ccchacha20_reset(ccchacha20_ctx *ctx);

/*!
 * @function ccchacha20
 * @abstract One-shot process data using ChaCha20.
 *
 * @param      key        Secret key
 * @param      nonce      The nonce to use
 * @param      counter    The starting counter value
 * @param      nbytes     Number of bytes to process
 * @param      in         Data to process
 * @param      out        Processed data
 */
int ccchacha20(const void *key, const void *nonce, uint32_t counter, size_t nbytes, const void *in, void *out);

/*!
 * @function ccpoly1305_init
 * @abstract Initialize a Poly1305 context.
 *
 * @param      ctx        The Poly1305 context
 * @param      key        Secret key used for authentication
 */
int ccpoly1305_init(ccpoly1305_ctx *ctx, const void *key);

/*!
 * @function ccpoly1305_update
 * @abstract Process data for Poly1305 authentication.
 *
 * @param      ctx        The Poly1305 context
 * @param      nbytes     Number of bytes that the data has
 * @param      in         The data to be authenticated
 */
int ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const void *in);

/*!
 * @function ccpoly1305_final
 * @abstract Finalize a Poly1305 tag.
 *
 * @param      ctx        The Poly1305 context
 * @param      tag        The generated authentication tag.
 */
int ccpoly1305_final(ccpoly1305_ctx *ctx, void *tag);

/*!
 * @function ccpoly1305
 * @abstract One-shot generate a Poly1305 authentication tag.
 *
 * @param      key        Secret key used for authentication
 * @param      nbytes     Number of bytes that the data has
 * @param      in         The data to be authenticated
 * @param      tag        The generated authentication tag.
 */
int ccpoly1305(const void *key, size_t nbytes, const void *in, void *tag);

#endif
