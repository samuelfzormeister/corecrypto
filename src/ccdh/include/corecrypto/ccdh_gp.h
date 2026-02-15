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

#ifndef _CORECRYPTO_CCDH_GP_H_
#define _CORECRYPTO_CCDH_GP_H_

#include <corecrypto/ccdh.h>

ccdh_const_gp_t ccdh_gp_apple768(void);
ccdh_const_gp_t ccdh_gp_rfc2409group02(void);
ccdh_const_gp_t ccdh_gp_rfc3526group05(void);
ccdh_const_gp_t ccdh_gp_rfc3526group14(void);
ccdh_const_gp_t ccdh_gp_rfc3526group15(void);
ccdh_const_gp_t ccdh_gp_rfc3526group16(void);
ccdh_const_gp_t ccdh_gp_rfc3526group17(void);
ccdh_const_gp_t ccdh_gp_rfc3526group18(void);
ccdh_const_gp_t ccdh_gp_rfc5114_MODP_1024_160(void);
ccdh_const_gp_t ccdh_gp_rfc5114_MODP_2048_224(void);
ccdh_const_gp_t ccdh_gp_rfc5114_MODP_2048_256(void);

#endif /* _CORECRYPTO_CCDH_GP_H_ */
