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

#include <iostream>
#include <sstream>
#include <string.h>
#include <string>

extern "C" {
#include <corecrypto/cctest_priv.h>
}

static bool trace = false;

static uint32_t flags = 0;

void set_flag(std::string &str)
{
    if (str == "md2") {
        flags |= CCTEST_ENABLE_MD2;
    }
    if (str == "md4") {
        flags |= CCTEST_ENABLE_MD4;
    }
    if (str == "aes") {
        flags |= CCTEST_ENABLE_AES;
    }
    if (str == "md5") {
        flags |= CCTEST_ENABLE_MD5;
    }
    if (str == "ripemd") {
        flags |= CCTEST_ENABLE_RIPEMD;
    }
    if (str == "sha1") {
        flags |= CCTEST_ENABLE_SHA1;
    }
    if (str == "sha2") {
        flags |= CCTEST_ENABLE_SHA2;
    }
}

void parse_test_list_string(std::string &enabled)
{
    std::stringstream stream(enabled);
    std::string m;

    while (std::getline(stream, m, ',')) {
        set_flag(m);
    }
}

//
// cctest -run aes-ecb,md4
//
void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "-trace") {
            trace = true;
        } else if (str == "-run") {
            std::string enabled = argv[i+1];
            if (enabled == "all") {
                flags = CCTEST_ENABLE_ALL;
            } else {
                parse_test_list_string(enabled);
            }
        }
    }
}

int main(int argc, const char *argv[])
{
    parse_args(argc, argv);
    cctest_enable_trace(trace);
    cctest_conduct_tests(flags);

    return 0;
}
