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

ccdigest_test_vector ccdigest_test_md4_vectors[] = {
    {
        CCTEST_ATTRS_NONE,
        "",
        0,
        "\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
    },
    {
        CCTEST_ATTRS_NONE,
        "The quick brown fox jumps over the lazy dog",
        sizeof("The quick brown fox jumps over the lazy dog")-1,
        "\x1b\xee\x69\xa4\x6b\xa8\x11\x18\x5c\x19\x47\x62\xab\xae\xae\x90"
    },
    {
        CCTEST_ATTRS_NONE,
        "Test vector from febooti.com",
        sizeof("Test vector from febooti.com")-1,
        "\x65\x78\xf2\x66\x4b\xc5\x6e\x0b\x5b\x3f\x85\xed\x26\xec\xc6\x7b"
    }
};
