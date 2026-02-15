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

#ifndef _CORECRYPTO_CCSRP_GP_H_
#define _CORECRYPTO_CCSRP_GP_H_

#include <corecrypto/ccsrp.h>

ccsrp_const_gp_t ccsrp_gp_rfc5054_1024(void);
ccsrp_const_gp_t ccsrp_gp_rfc5054_2048(void);
ccsrp_const_gp_t ccsrp_gp_rfc5054_3072(void);
ccsrp_const_gp_t ccsrp_gp_rfc5054_4096(void);
ccsrp_const_gp_t ccsrp_gp_rfc5054_8192(void);

#endif /* _CORECRYPTO_CCSRP_GP_H_ */
