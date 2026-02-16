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

static struct ccdigest_test_vector SHA224LongMsg[] = {
#include "vectors/SHA224LongMsg.inc"
};

static struct ccdigest_test_vector SHA224ShortMsg[] = {
#include "vectors/SHA224ShortMsg.inc"
};

CCDIGEST_TEST_NAMED_FACTORY(longmsg, sha224_ltc, SHA224LongMsg, "LTC SHA-224 (SHA224LongMsg)");
CCDIGEST_TEST_NAMED_FACTORY(shortmsg, sha224_ltc, SHA224ShortMsg, "LTC SHA-224 (SHA224ShortMsg)");
