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

#ifndef _CORECRYPTO_CCAES_INTEL_VNG_H_
#define _CORECRYPTO_CCAES_INTEL_VNG_H_

#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include <stdint.h>

#if CCAES_INTEL_ASM

/*
 * ZORMEISTER:
 * So as it turns out, a lot of the initial corecrypto codebase might have been based off of the LibTomCrypt version
 * found in CommonCrypto-55010
 *
 * A lot of source code for implementations was reused from LTC, and what has me interested is the mention of
 * Gladman AES in the context of AES-CBC.
 *
 */

enum {
    CRYPT_OK=0,             /* Result OK */
    CRYPT_ERROR,            /* Generic Error */
    CRYPT_NOP,              /* Not a failure but no operation was performed */

    CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
    CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
    CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

    CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
    CRYPT_INVALID_PACKET,   /* Invalid input packet given */

    CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
    CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

    CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
    CRYPT_INVALID_HASH,     /* Invalid hash specified */
    CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

    CRYPT_MEM,              /* Out of memory */

    CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
    CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

    CRYPT_INVALID_ARG,      /* Generic invalid argument */
    CRYPT_FILE_NOTFOUND,    /* File Not Found */

    CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */
    CRYPT_PK_INVALID_SYSTEM,/* Invalid PK system specified */
    CRYPT_PK_DUP,           /* Duplicate key already in key ring */
    CRYPT_PK_NOT_FOUND,     /* Key not found in keyring */
    CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

    CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
    CRYPT_PK_INVALID_PADDING,/* Invalid padding on input */

    CRYPT_HASH_OVERFLOW,     /* Hash applied to too many bits */
    CRYPT_UNIMPLEMENTED,     /* called an unimplemented routine through a function table */
    CRYPT_PARAM,                /* Parameter Error */

    CRYPT_FALLBACK           /* Accelerator was called, but the input didn't meet minimum criteria - fallback to software */
};

#define VNG_INTEL_KS_LENGTH       60

typedef struct {
    uint32_t ks[VNG_INTEL_KS_LENGTH];
    uint32_t rounds;
} vng_aes_intel_encrypt_ctx;

typedef struct {
    uint32_t ks[VNG_INTEL_KS_LENGTH];
    uint32_t rounds;
} vng_aes_intel_decrypt_ctx;

typedef struct {
    vng_aes_intel_encrypt_ctx encrypt;
	vng_aes_intel_decrypt_ctx decrypt;
} vng_aes_intel_ctx;

extern int vng_aes_encrypt_opt_key(const unsigned char *key, size_t key_len, vng_aes_intel_encrypt_ctx cx[1]) __asm__("_vng_aes_encrypt_opt_key");
extern int vng_aes_encrypt_aesni_key(const unsigned char *key, size_t key_len, vng_aes_intel_encrypt_ctx cx[1]) __asm__("_vng_aes_encrypt_aesni_key");

extern int vng_aes_decrypt_opt_key(const unsigned char *key, size_t key_len, vng_aes_intel_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_opt_key");
extern int vng_aes_decrypt_aesni_key(const unsigned char *key, size_t key_len, vng_aes_intel_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_aesni_key");

extern int vng_aes_encrypt_aesni(const unsigned char *pt, unsigned char *ct, vng_aes_intel_encrypt_ctx *ctx) __asm__("_vng_aes_encrypt_aesni");
extern int vng_aes_encrypt_opt(const unsigned char *pt, unsigned char *ct, vng_aes_intel_encrypt_ctx *ctx) __asm__("_vng_aes_encrypt_opt");

extern int vng_aes_decrypt_aesni(const unsigned char *ct, unsigned char *pt, vng_aes_intel_decrypt_ctx *ctx) __asm__("_vng_aes_decrypt_aesni");
extern int vng_aes_decrypt_opt(const unsigned char *ct, unsigned char *pt, vng_aes_intel_decrypt_ctx *ctx) __asm__("_vng_aes_decrypt_opt");

extern int vng_aes_decrypt_opt_cbc(const unsigned char *ibuf, unsigned char *in_iv, size_t num_blk,
                              unsigned char *obuf, const vng_aes_intel_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_opt_cbc");
extern int vng_aes_encrypt_opt_cbc(const unsigned char *ibuf, unsigned char *in_iv, size_t num_blk,
                              unsigned char *obuf, const vng_aes_intel_encrypt_ctx ctx[1]) __asm__("_vng_aes_encrypt_opt_cbc");

extern int vng_aes_decrypt_aesni_cbc(const unsigned char *ibuf, unsigned char *in_iv, size_t num_blk,
                              unsigned char *obuf, const vng_aes_intel_decrypt_ctx cx[1]) __asm__("_vng_aes_decrypt_aesni_cbc");
extern int vng_aes_encrypt_aesni_cbc(const unsigned char *ibuf, unsigned char *in_iv, size_t num_blk,
                              unsigned char *obuf, const vng_aes_intel_encrypt_ctx ctx[1]) __asm__("_vng_aes_encrypt_aesni_cbc");

/* accessors to the assembly code */
extern void aesxts_mult_x(uint8_t *I) __asm__("_aesxts_mult_x");

extern int aesxts_tweak_crypt_aesni(const uint8_t *P, uint8_t *C, const uint8_t *T, vng_aes_intel_encrypt_ctx *ctx) __asm__("_aesxts_tweak_crypt_aesni");
extern int aesxts_tweak_crypt_opt(const uint8_t *P, uint8_t *C, const uint8_t *T, vng_aes_intel_encrypt_ctx *ctx) __asm__("_aesxts_tweak_crypt_opt");

extern int aesxts_tweak_crypt_group_aesni(const uint8_t *P, uint8_t *C, const uint8_t *T, vng_aes_intel_encrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_crypt_group_aesni");
extern int aesxts_tweak_crypt_group_opt(const uint8_t *P, uint8_t *C, const uint8_t *T, vng_aes_intel_encrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_crypt_group_opt");

extern int aesxts_tweak_uncrypt_aesni(const uint8_t *C, uint8_t *P, const uint8_t *T, vng_aes_intel_decrypt_ctx *ctx) __asm__("_aesxts_tweak_uncrypt_aesni");
extern int aesxts_tweak_uncrypt_opt(const uint8_t *C, uint8_t *P, const uint8_t *T, vng_aes_intel_decrypt_ctx *ctx) __asm__("_aesxts_tweak_uncrypt_opt");

extern int aesxts_tweak_uncrypt_group_aesni(const uint8_t *C, uint8_t *P, const uint8_t *T, vng_aes_intel_decrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_uncrypt_group_aesni");
extern int aesxts_tweak_uncrypt_group_opt(const uint8_t *C, uint8_t *P, const uint8_t *T, vng_aes_intel_decrypt_ctx *ctx, uint32_t lim) __asm__("_aesxts_tweak_uncrypt_group_opt");

int vng_aes_xts_encrypt_aesni(
   const uint8_t *pt, unsigned long ptlen,
         uint8_t *ct,
   const uint8_t *tweak,
         void *ctx);

int vng_aes_xts_encrypt_opt(
   const uint8_t *pt, unsigned long ptlen,
         uint8_t *ct,
   const uint8_t *tweak,
         void *ctx);

int vng_aes_xts_decrypt_aesni(
   const uint8_t *ct, unsigned long ptlen,
         uint8_t *pt,
   const uint8_t *tweak,
         void *ctx);

int vng_aes_xts_decrypt_opt(
   const uint8_t *ct, unsigned long ptlen,
         uint8_t *pt,
   const uint8_t *tweak,
         void *ctx);

#endif

#endif
