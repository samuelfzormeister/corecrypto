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

#include <corecrypto/ccdigest_test_internal.h>

/*
 * sourced from: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */

static ccdigest_test_vector ccdigest_test_rmd160_vectors[] = {
    {
        CCTEST_ATTRS_NONE,
        "",
        0,
        "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31"
    },
    {
        CCTEST_ATTRS_NONE,
        "a",
        sizeof("a")-1,
        "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe"
    },
    {
        CCTEST_ATTRS_NONE,
        "abc",
        sizeof("abc")-1,
        "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc"
    },
    {
        CCTEST_ATTRS_NONE,
        "message digest",
        sizeof("message digest")-1,
        "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36"
    },
    {
        CCTEST_ATTRS_NONE,
        "abcdefghijklmnopqrstuvwxyz",
        sizeof("abcdefghijklmnopqrstuvwxyz")-1,
        "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb\xdc\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc"
    },
    {
        CCTEST_ATTRS_NONE,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        sizeof("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")-1,
        "\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed\x3a\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89"
    },
    {
        CCTEST_ATTRS_NONE,
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        sizeof("12345678901234567890123456789012345678901234567890123456789012345678901234567890")-1,
        "\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb\xd3\x32\x3c\xab\x82\xbf\x63\x32\x6b\xfb"
    }
};
