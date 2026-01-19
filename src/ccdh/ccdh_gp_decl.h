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

#ifndef _CORECRYPTO_CCDH_GP_DECL_H
#define _CORECRYPTO_CCDH_GP_DECL_H

#include <corecrypto/cczp.h>

#define ccdh_gp_decl_n(n)     \
    struct {                  \
        cc_size ccn_size;     \
        cc_unit bitlen;       \
        ccmod_func_t zp_func; \
        cc_unit p[(n)];       \
        cc_unit r[(n+1)];     \
        cc_unit g[(n)];       \
        cc_unit order[(n)];   \
        cc_unit l;            \
    }

#endif
