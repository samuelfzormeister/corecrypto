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

#include <corecrypto/ccckg.h>
#include <corecrypto/cc_stub_diag.h>

size_t ccckg_sizeof_commitment(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    cc_stub_log_abort(__FUNCTION__);
}

size_t ccckg_sizeof_opening(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    cc_stub_log_abort(__FUNCTION__);
}

size_t ccckg_sizeof_share(ccec_const_cp_t cp, const struct ccdigest_info *di)
{
    cc_stub_log_abort(__FUNCTION__);
}

void ccckg_init(ccckg_ctx_t *ctx,
               ccec_const_cp_t cp,
               const struct ccdigest_info *di,
               const struct ccrng_state *rng)
{
    cc_stub_log_abort(__FUNCTION__);
}
