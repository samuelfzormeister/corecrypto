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

static ccdigest_test_vector ccdigest_test_rfc1321_vectors[] = {
    {
        CCTEST_ATTRS_NONE,
        "",
        0,
        "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
    },
    {
        CCTEST_ATTRS_NONE,
        "a",
        sizeof("a")-1,
        "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
    },
    {
        CCTEST_ATTRS_NONE,
        "abc",
        sizeof("abc")-1,
        "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"
    },
    {
        CCTEST_ATTRS_NONE,
        "message digest",
        sizeof("message digest")-1,
        "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
    },
    {
        CCTEST_ATTRS_NONE,
        "abcdefghijklmnopqrstuvwxyz",
        sizeof("abcdefghijklmnopqrstuvwxyz")-1,
        "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"
    },
    {
        CCTEST_ATTRS_NONE,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        sizeof("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")-1,
        "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f"
    },
    {
        CCTEST_ATTRS_NONE,
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        sizeof("12345678901234567890123456789012345678901234567890123456789012345678901234567890")-1,
        "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a"
    }
};
