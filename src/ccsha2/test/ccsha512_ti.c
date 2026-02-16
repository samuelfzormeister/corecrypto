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

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdigest_test_internal.h>

static struct ccdigest_test_vector SHA512LongMsg[] = {
#include "vectors/SHA512LongMsg.inc"
};

static struct ccdigest_test_vector SHA512ShortMsg[] = {
#include "vectors/SHA512ShortMsg.inc"
};

CCDIGEST_TEST_NAMED_FACTORY(longmsg, sha512_ltc, SHA512LongMsg, "LTC SHA-512 (SHA512LongMsg)");
CCDIGEST_TEST_NAMED_FACTORY(shortmsg, sha512_ltc, SHA512ShortMsg, "LTC SHA-512 (SHA512ShortMsg)");
