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

#include <rsplib/base.hpp>
#include <rsplib/aesvs.hpp>
#include <rsplib/osl.hpp>
#include <memory>
#include <sstream>
#include <string>
#include <regex>

using namespace corecrypto::rsplib;
using namespace corecrypto;

parser::parser(const std::string &basename, std::stringstream &stream)
{
    osl::log(osl::debug, "parser::parser enter >>");
    _basename = basename;
    //
    // RSP headers usually have a marker at the beginning.
    //
    std::string line;

    while (std::getline(stream, line)) {
        osl::log(osl::debug, "parser: cur line: %s", line.c_str());
        if (line.find("AESVS") != std::string::npos) {
            if (line.find("ECB") == std::string::npos) {
                parse_for_aesvs(stream, false);
            } else {
                parse_for_aesvs(stream, true);
            }
            break;
        }
    }
    osl::log(osl::debug, "parser::parser exit <<");
}

//
// This is shit. This is shit. Can someone that isn't me write anything better.
//
void parser::parse_for_aesvs(std::stringstream &stream, bool ecb)
{
    osl::log(osl::debug, "parsing aesvs...");
    std::string line;
    std::string key;
    std::string iv;
    std::string plaintext;
    std::string ciphertext;

    auto encrypt = std::make_shared<aesvs_test>(_basename + "_encrypt");
    auto decrypt = std::make_shared<aesvs_test>(_basename + "_decrypt");

    bool curEnc = false;

    while (std::getline(stream, line)) {
        std::smatch match;
        std::regex reg("(\\w+$)");
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
            key = match.str();
        }

        if (line.find("PLAINTEXT") != std::string::npos) {
            std::regex_search(line, match, reg);
            plaintext = match.str();
        }

        if (line.find("CIPHERTEXT") != std::string::npos) {
            std::regex_search(line, match, reg);
            ciphertext = match.str();

            if (ecb) {
                auto vector = std::make_shared<aesvs_vector>(key, iv, plaintext, ciphertext);
                if (curEnc) {
                    encrypt->add_vector(vector);
                } else {
                    decrypt->add_vector(vector);
                }
            }
        }

        if (line.find("IV") != std::string::npos) {
            std::regex_search(line, match, reg);
            iv = match.str();

            auto vector = std::make_shared<aesvs_vector>(key, iv, plaintext, ciphertext);
            if (curEnc) {
                encrypt->add_vector(vector);
            } else {
                decrypt->add_vector(vector);
            }
        }
    }

    _tests.push_back(encrypt);
    _tests.push_back(decrypt);
}


void parser::write_tests_to_stream(std::stringstream &stream) {
    stream << "/*" << std::endl;
    stream << " * Copyright (C) 2026 The PureDarwin Project, All rights reserved." << std::endl;
    stream << " * " << std::endl;
    stream << " * @LICENSE_HEADER_BEGIN@" << std::endl;
    stream << " * Licensed under the Apache License, Version 2.0 (the \"License\");" << std::endl;
    stream << " * you may not use this file except in compliance with the License." << std::endl;
    stream << " * You may obtain a copy of the License at" << std::endl;
    stream << " * " << std::endl;
    stream << " *     http://www.apache.org/licenses/LICENSE-2.0" << std::endl;
    stream << " * " << std::endl;
    stream << " * Unless required by applicable law or agreed to in writing, software" << std::endl;
    stream << " * distributed under the License is distributed on an \"AS IS\" BASIS," << std::endl;
    stream << " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied." << std::endl;
    stream << " * See the License for the specific language governing permissions and" << std::endl;
    stream << " * limitations under the License." << std::endl;
    stream << " * @LICENSE_HEADER_END@" << std::endl;
    stream << " */" << std::endl;
    stream << std::endl;
    stream << "//" << std::endl;
    stream << "// THIS FILE HAS BEEN AUTOMATICALLY GENERATED BY RSPLIB" << std::endl;
    stream << "//" << std::endl;
    stream << std::endl;

    for (int i = 0; i < _tests.size(); i++) {
        _tests[i]->write_to_stream(stream);
        stream << std::endl;
    }
}
