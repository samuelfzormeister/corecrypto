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

#ifndef _CORECRYPTO_CCXOF_H_
#define _CORECRYPTO_CCXOF_H_

#include <corecrypto/cc.h>

/*
 zormeister@Zormeisters-Mac-Pro ~ % nm /Volumes/Developer/Binaries/Apple/15.2/KDK.pkg/Payload/System/Library/Extensions/corecrypto.kext/Contents/MacOS/corecrypto | grep shake
    000000000001de4e T _ccshake128
    000000000001dd18 t _ccshake128_c_absorb
    000000000001dd33 t _ccshake128_c_absorb_last
    000000000001dd54 t _ccshake128_c_squeeze
    000000000001dcc1 t _ccshake128_vng_absorb
    000000000001dcdc t _ccshake128_vng_absorb_last
    000000000001dcfd t _ccshake128_vng_squeeze
    000000000001dc9d T _ccshake128_xi
    000000000001df01 T _ccshake256
    000000000001ddea t _ccshake256_c_absorb
    000000000001de05 t _ccshake256_c_absorb_last
    000000000001de26 t _ccshake256_c_squeeze
    000000000001dd93 t _ccshake256_vng_absorb
    000000000001ddae t _ccshake256_vng_absorb_last
    000000000001ddcf t _ccshake256_vng_squeeze
    000000000001dd6f T _ccshake256_xi
    000000000001de41 T _ccshake_init
    00000000000839a8 s _ccxof_shake128_c_xi
    0000000000083978 s _ccxof_shake128_vng_xi
    0000000000083a08 s _ccxof_shake256_c_xi
    00000000000839d8 s _ccxof_shake256_vng_xi
 zormeister@Zormeisters-Mac-Pro ~ % nm /Volumes/Developer/Binaries/Apple/15.2/KDK.pkg/Payload/System/Library/Extensions/corecrypto.kext/Contents/MacOS/corecrypto | grep xof
    00000000000412f7 T _ccxof_absorb
    00000000000412da T _ccxof_init
    00000000000839a8 s _ccxof_shake128_c_xi
    0000000000083978 s _ccxof_shake128_vng_xi
    0000000000083a08 s _ccxof_shake256_c_xi
    00000000000839d8 s _ccxof_shake256_vng_xi
    00000000000413ea T _ccxof_squeeze
 */

struct ccxof_info {};

// found in 15.2 corecrypto.kext by running NM
const struct ccxof_info *ccshake128_xi(void);
const struct ccxof_info *ccshake256_xi(void);

#endif
