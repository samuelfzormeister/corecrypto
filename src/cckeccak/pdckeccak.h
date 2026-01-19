//
//  pdckeccak.h
//  corecrypto
//
//  Created by Zormeister on 21/1/2025.
//

#ifndef PDCRYPTO_KECCAK_H
#define PDCRYPTO_KECCAK_H

#include <corecrypto/cc.h>

/* This is nowhere near the avaiable keccak functions in mainstream CC, but this is good enough */

#define CC_KECCAK_MAX_ROW    4
#define CC_KECCAK_MAX_COLUMN 4
#define CC_KECCAK_MAX_DEPTH  64

struct pdckeccak_state {
    union {
        uint8_t raw_state[(CC_KECCAK_MAX_ROW * CC_KECCAK_MAX_COLUMN * CC_KECCAK_MAX_DEPTH) / 8];
    } keccak_state;
};

typedef struct pdckeccak_state *pdckeccak_state_t;

#endif /* PDCRYPTO_KECCAK_H */
