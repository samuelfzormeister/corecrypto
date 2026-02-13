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

#include <cstring>
#include <rsplib/osl.hpp>

using namespace corecrypto;

void util::write_hex_string(std::stringstream &stream, const std::string &string)
{
    const char *c_str = string.c_str();
    size_t len;

    //
    // We'll use a bunch of libc here to accomplish our goal.
    //
    len = strlen(c_str);
    stream << "\"";
    for (size_t i = 0; i < len; i += 2) {
        stream << "\\x" << c_str[i];
        stream << c_str[i+1];
    }
    stream << "\"";
}