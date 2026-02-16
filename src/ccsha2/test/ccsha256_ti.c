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

static struct ccdigest_test_vector SHA256LongMsg[] = {
#include "vectors/SHA256LongMsg.inc"
};

static struct ccdigest_test_vector SHA256ShortMsg[] = {
#include "vectors/SHA256ShortMsg.inc"
};

CCDIGEST_TEST_NAMED_FACTORY(longmsg, sha256_ltc, SHA256LongMsg, "LTC SHA-256 (SHA256LongMsg)");
CCDIGEST_TEST_NAMED_FACTORY(shortmsg, sha256_ltc, SHA256ShortMsg, "LTC SHA-256 (SHA256ShortMsg)");
