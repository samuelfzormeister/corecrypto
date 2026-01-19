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

#include "RSPParser.hpp"
#include <vector>
#include <cstring>

using namespace CoreCrypto::RSP;

enum struct KeyType {
    Input,
    Output,
    Key,
    IV,
    Tag,
    AAD,
    MsgLength
};

/*
 * 'enter' key is encoded as 0D 0A according to Okteta.
 */

struct KeyMapping {
    const char * Key;
    KeyType Type;
    Test::Operation Operation;
};

KeyMapping gParsingMap[] = {
    {"Len", KeyType::MsgLength, Test::Operation::Hash},
    {"Msg", KeyType::Input, Test::Operation::Hash},
    {"MD", KeyType::Output, Test::Operation::Hash},
    {"Key", KeyType::Key, Test::Operation::Decrypt},
    {"KEY", KeyType::Key, Test::Operation::Decrypt},
    {"IV", KeyType::IV, Test::Operation::Decrypt},
    {"Key", KeyType::Key, Test::Operation::Encrypt},
    {"KEY", KeyType::Key, Test::Operation::Encrypt},
    {"IV", KeyType::IV, Test::Operation::Encrypt},
    {"PLAINTEXT", KeyType::Input, Test::Operation::Encrypt},
    {"CIPHERTEXT", KeyType::Output, Test::Operation::Encrypt},
    {"PLAINTEXT", KeyType::Output, Test::Operation::Decrypt},
    {"CIPHERTEXT", KeyType::Input, Test::Operation::Decrypt},
};

/* This expects that the rsp vector is set on the first byte of the first */
Test::Test(std::vector<char> rsp, Test::Operation op) {
    this->_operation = op;

    size_t pos = 0;
    size_t max = rsp.size();

    while (pos < max) {
        for (int i = 0; i < sizeof(gParsingMap) / sizeof(KeyMapping); i++) {
            if (strncmp(rsp.data(), gParsingMap[i].Key, strlen(gParsingMap[i].Key)) == 0) {

            }
        }
    }
}
