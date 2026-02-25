//  Created by rafirafi on 3/17/16.
//  Copyright (c) 2016 rafirafi. All rights reserved.

#ifndef PDCRYPTO_DUMMY_H
#define PDCRYPTO_DUMMY_H

#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccrc4.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrsa.h>

extern const struct ccmode_gcm pdcaes_gcm_encrypt_dummy;
extern const struct ccmode_gcm pdcaes_gcm_decrypt_dummy;

#endif // PDCRYPTO_DUMMY_H
