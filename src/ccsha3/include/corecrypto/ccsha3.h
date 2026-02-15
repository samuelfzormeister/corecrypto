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

#ifndef _CORECRYPTO_CCSHA3_H_
#define _CORECRYPTO_CCSHA3_H_

#include <corecrypto/ccdigest.h>

/* SHA-3 implementation, because we need that as of CommonCrypto from Darwin 20-ish */

const struct ccdigest_info *ccsha3_224_di(void);
const struct ccdigest_info *ccsha3_256_di(void);
const struct ccdigest_info *ccsha3_384_di(void);
const struct ccdigest_info *ccsha3_512_di(void);

/*
 * RESEARCH SOURCES:
 *  - https://datatracker.ietf.org/doc/rfc9688/
 */

/* Consult NIST FIPS 202 for more info */


/*
 000000000004bcce t _ccsha3_224_c_compress
 000000000008f188 S _ccsha3_224_c_di
 000000000004bcea t _ccsha3_224_c_final
 000000000004bcfb T _ccsha3_224_di
 000000000004bd1f t _ccsha3_224_vng_compress
 000000000008f1d8 s _ccsha3_224_vng_di
 000000000004bd3b t _ccsha3_224_vng_final
 000000000004bf60 t _ccsha3_256_c_compress
 000000000008f368 S _ccsha3_256_c_di
 000000000004bf7c t _ccsha3_256_c_final
 000000000004bf8d T _ccsha3_256_di
 000000000004bfb1 t _ccsha3_256_vng_compress
 000000000008f3b8 s _ccsha3_256_vng_di
 000000000004bfcd t _ccsha3_256_vng_final
 000000000004bd4c t _ccsha3_384_c_compress
 000000000008f228 S _ccsha3_384_c_di
 000000000004bd68 t _ccsha3_384_c_final
 000000000004bd79 T _ccsha3_384_di
 000000000004bd9d t _ccsha3_384_vng_compress
 000000000008f278 s _ccsha3_384_vng_di
 000000000004bdb9 t _ccsha3_384_vng_final
 000000000004bdca t _ccsha3_512_c_compress
 000000000008f2c8 S _ccsha3_512_c_di
 000000000004bde6 t _ccsha3_512_c_final
 000000000004bdf7 T _ccsha3_512_di
 000000000004be1b t _ccsha3_512_vng_compress
 000000000008f318 s _ccsha3_512_vng_di
 000000000004be37 t _ccsha3_512_vng_final
 000000000004be50 T _ccsha3_final
 000000000007ffa0 S _ccsha3_keccak_p1600_initial_state

 */

/* See ccsha2.h for an explaination on the OIDs here */
#define ccoid_sha3_224 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07")
#define ccoid_sha3_224_len 11

#define ccoid_sha3_256 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08")
#define ccoid_sha3_256_len 11

#define ccoid_sha3_384 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09")
#define ccoid_sha3_384_len 11

#define ccoid_sha3_512 ((unsigned char *)"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0A")
#define ccoid_sha3_512_len 11

/* Thanks to my good old pal NM, I found out symbols for the C impls. */

#define CCSHA3_224_BLOCK_SIZE 144
#define CCSHA3_224_OUTPUT_SIZE 28
#define CCSHA3_224_STATE_SIZE 200
extern const struct ccdigest_info ccsha3_224_c_di;

#define CCSHA3_256_BLOCK_SIZE 136
#define CCSHA3_256_OUTPUT_SIZE 32
#define CCSHA3_256_STATE_SIZE 200
extern const struct ccdigest_info ccsha3_256_c_di;

#define CCSHA3_384_BLOCK_SIZE 104
#define CCSHA3_384_OUTPUT_SIZE 48
#define CCSHA3_384_STATE_SIZE 200
extern const struct ccdigest_info ccsha3_384_c_di;

#define CCSHA3_512_BLOCK_SIZE 72
#define CCSHA3_512_OUTPUT_SIZE 64
#define CCSHA3_512_STATE_SIZE 200
extern const struct ccdigest_info ccsha3_512_c_di;


#endif /* _CORECRYPTO_CCSHA3_H_ */
