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
        "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69\x27\x73"
    },
    {
        CCTEST_ATTRS_NONE,
        "The quick brown fox jumps over the lazy dog",
        sizeof("The quick brown fox jumps over the lazy dog")-1,
        "\x03\xd8\x5a\x0d\x62\x9d\x2c\x44\x2e\x98\x75\x25\x31\x9f\xc4\x71"
    },
    {
        CCTEST_ATTRS_NONE,
        "Test vector from febooti.com",
        sizeof("Test vector from febooti.com")-1,
        "\xdb\x12\x8d\x6e\x0d\x20\xa1\x19\x2a\x6b\xd1\xfa\xde\x40\x11\x50"
    }
};
