//
//  pdcxof.h
//  corecrypto
//
//  Created by Zormeister on 22/1/2025.
//

#ifndef PDCRYPTO_XOF_H
#define PDCRYPTO_XOF_H

#include <corecrypto/cc.h>

/* This is nowhere near the avaiable XOF functions in mainstream CC, but this is good enough */

struct pdcxof_info {
    size_t block_size;
};

#endif /* PDCRYPTO_XOF_H */
