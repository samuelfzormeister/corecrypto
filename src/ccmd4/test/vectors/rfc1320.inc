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

#include <corecrypto/ccdigest_test_internal.h>

static ccdigest_test_vector ccdigest_test_rfc1320_vectors[] = {
    {
        CCTEST_ATTRS_NONE,
        "",
        0,
        "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
    },
    {
        CCTEST_ATTRS_NONE,
        "a",
        sizeof("a")-1,
        "\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24"
    },
    {
        CCTEST_ATTRS_NONE,
        "abc",
        sizeof("abc")-1,
        "\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f\xc1\x0a\xe8\x7a\xa6\x72\x9d"
    },
    {
        CCTEST_ATTRS_NONE,
        "message digest",
        sizeof("message digest")-1,
        "\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b"
    },
    {
        CCTEST_ATTRS_NONE,
        "abcdefghijklmnopqrstuvwxyz",
        sizeof("abcdefghijklmnopqrstuvwxyz")-1,
        "\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee\xa8\xed\x63\xdf\x41\x2d\xa9"
    },
    {
        CCTEST_ATTRS_NONE,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        sizeof("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")-1,
        "\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c\xe6\x27\xe1\x53\xe7\xf0\xe4"
    },
    {
        CCTEST_ATTRS_NONE,
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        sizeof("12345678901234567890123456789012345678901234567890123456789012345678901234567890")-1,
        "\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c\x3e\x7b\x16\x4f\xcc\x05\x36"
    }
};
