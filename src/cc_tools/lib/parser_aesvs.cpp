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

#include <rsplib/parser.hpp>
#include <rsplib/osl.hpp>
#include <memory>
#include <sstream>
#include <string>
#include <regex>

using namespace corecrypto::rsplib;
using namespace corecrypto;

//
// This is shit. This is shit. Can someone that isn't me write anything better.
//
void parser::parse_aesvs(std::stringstream &stream, aesvs_test::mode mode)
{
    osl::log(osl::debug, "parsing aesvs...");
    std::string line;
    std::string key;
    std::string iv;
    std::string plaintext;
    std::string ciphertext;

    auto encrypt = std::make_shared<aesvs_test>(_basename + "_encrypt", mode);
    auto decrypt = std::make_shared<aesvs_test>(_basename + "_decrypt", mode);

    bool curEnc = false;

    while (std::getline(stream, line)) {
        std::smatch match;
        std::regex reg("(\\S+)\\s*$");
        std::regex repl("\\s+");
        osl::log(osl::debug, "parser: cur line: %s", line.c_str());
        if (line.find("[ENCRYPT]") != std::string::npos) {
            curEnc = true;
        }
        if (line.find("[DECRYPT]") != std::string::npos) {
            curEnc = false;
        }

        //
        // There is a sequence to this.
        //
        if (line.find("KEY") != std::string::npos) {
            std::regex_search(line, match, reg);
            osl::log(osl::debug, "parser: found key");
            key = std::regex_replace(match.str(), repl, "");
        }
        
        if (line.find("IV") != std::string::npos) {
            std::regex_search(line, match, reg);
            iv = std::regex_replace(match.str(), repl, "");
            osl::log(osl::debug, "parser: found iv");
        }

        if (curEnc) {
            if (line.find("PLAINTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                osl::log(osl::debug, "parser: found pt");
                plaintext = std::regex_replace(match.str(), repl, "");
                osl::log(osl::debug, "parser: %s", plaintext.c_str());
            }

            if (line.find("CIPHERTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                osl::log(osl::debug, "parser: found ct");
                ciphertext = std::regex_replace(match.str(), repl, "");
                osl::log(osl::debug, "parser: %s", ciphertext.c_str());
                auto vector = std::make_shared<aesvs_vector>(key, iv, plaintext, ciphertext);
                encrypt->add_vector(vector);
            }
        } else {
            if (line.find("CIPHERTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                osl::log(osl::debug, "parser: found ct");
                ciphertext = std::regex_replace(match.str(), repl, "");
                osl::log(osl::debug, "parser: %s", ciphertext.c_str());
            }

            if (line.find("PLAINTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                osl::log(osl::debug, "parser: found pt");
                plaintext = std::regex_replace(match.str(), repl, "");
                osl::log(osl::debug, "parser: %s", plaintext.c_str());
                auto vector = std::make_shared<aesvs_vector>(key, iv, plaintext, ciphertext);
                decrypt->add_vector(vector);
            }
        }
    }

    _tests.push_back(encrypt);
    _tests.push_back(decrypt);
}
