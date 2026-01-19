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

#include <optional>
#include <string>
#include <vector>
#include <cstdint>

/* Make this clean in case this gets reused anywhere. */
namespace CoreCrypto {

    namespace RSP {

        class Test {
            public:
            enum struct Operation {
                Hash,
                Encrypt,
                Decrypt,
            };

            public:
            Test(std::vector<char> rspData, Operation op); /* op should be fed by the parser. */

            const std::vector<uint8_t> &getInputData() { return _input; };
            const std::vector<uint8_t> &getExpectedResult() { return _expected; };
            const std::vector<uint8_t> &getInitializationVector() { return _iv; };
            const std::vector<uint8_t> &getMAC() { return _mac; };
            const std::vector<uint8_t> &getTag() { return _tag; };

            const size_t getLength();

            const Operation getOperation();

            const bool isHashTest() { return _operation == Operation::Hash; };
            const bool hasIV() { return _hasIV; };
            const bool hasKey() { return _hasKey; };
            const bool hasAAD() { return _hasAAD; };
            const bool hasTag() { return _hasTag; };

            private:
            Operation _operation;

            bool _hasIV {false};
            bool _hasAAD {false};
            bool _hasKey {false};
            bool _hasTag {false};

            std::vector<uint8_t> _input;
            std::vector<uint8_t> _expected;
            std::vector<uint8_t> _iv;
            std::vector<uint8_t> _add;
            std::vector<uint8_t> _tag;
            std::vector<uint8_t> _mac;
        };

        class Parser {
            public:
            Parser(std::vector<char> rsp);

            std::vector<Test> GetTestVectors();
        };

    }

};
