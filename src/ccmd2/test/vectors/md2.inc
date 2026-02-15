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

#include <corecrypto/ccdigest_test_internal.h>

ccdigest_test_vector ccdigest_test_md2_vectors[] = {
    {
        CCTEST_ATTRS_NONE,
        "",
        0,
        // 83 50 e5 a3 e2 4c 15 3d f2 27 5c 9f 80 69 27 73
        "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69\x27\x73"
    },
    {
        CCTEST_ATTRS_NONE,
        "a",
        sizeof("a")-1,
        "\x32\xec\x01\xec\x4a\x6d\xac\x72\xc0\xab\x96\xfb\x34\xc0\xb5\xd1"
    },
    {
        CCTEST_ATTRS_NONE,
        "abc",
        sizeof("abc")-1,
        "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b\x30\x28\x3a\x69\xe6\xde\xd6\xbb"
    },
    {
        CCTEST_ATTRS_NONE,
        "message digest",
        sizeof("message digest")-1,
        "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b\x21\x9f\xf3\x30\x31\xfe\x06\xb0"
    },
    {
        CCTEST_ATTRS_NONE,
        "abcdefghijklmnopqrstuvwxyz",
        sizeof("abcdefghijklmnopqrstuvwxyz")-1,
        "\x4e\x8d\xdf\xf3\x65\x02\x92\xab\x5a\x41\x08\xc3\xaa\x47\x94\x0b"
    },
    {
        CCTEST_ATTRS_NONE,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        sizeof("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")-1,
        "\xda\x33\xde\xf2\xa4\x2d\xf1\x39\x75\x35\x28\x46\xc3\x03\x38\xcd"
    },
    {
        CCTEST_ATTRS_NONE,
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        sizeof("12345678901234567890123456789012345678901234567890123456789012345678901234567890")-1,
        "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9\x80\x6c\x3c\x66\xf3\xef\xd8"
    }
};
