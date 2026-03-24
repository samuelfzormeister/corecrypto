/*
 * Copyright (C) 2026 The PureDarwin Project, All rights reserved.
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

#ifndef _CORECRYPTO_FIPSPOST_H_
#define _CORECRYPTO_FIPSPOST_H_

/*
 * Apple corecrypto has the __TEXT section __fips_hmac for verifying its integrity.
 * 
 * This was found in the dyld project, as it recomputes the HMAC when inserting libcorecrypto
 * into the dyld shared cache.
 *
 * There's also the /usr/libexec/cc_fips_test binary that gets ran by launchd as a boot task.
 *
 * I still don't know what the "fipspost_trace_vtable" variable is for.
 *
 * The FIPS integrity test runs a HMAC on the __TEXT,__text section of the dylib or kext.
 *
 * The HMAC is SHA-256 based, I suppose, given that the section is 32 bytes in length.
 *
 * It would also be nice if we could sign/notarize ourself for the kernel.
 *
 * Maybe for the future. 
 */

void ccfips_enter(void);

/*
 * Function prototypes.
 */

int ccfips_integrity_begin(void);

#endif /* _CORECRYPTO_FIPSPOST_H_ */
