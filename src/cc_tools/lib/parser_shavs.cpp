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
#include <rsplib/shavs.hpp>
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
void parser::parse_shavs(std::stringstream &stream, shavs_test::variant variant)
{
    osl::log(osl::debug, "parsing aesvs...");
    std::string line;
    std::string msg;
    std::string dgst;
    std::string len;

    auto test = std::make_shared<shavs_test>(_basename, variant);

    while (std::getline(stream, line)) {
        std::smatch match;
        std::regex reg("(\\S+)\\s*$");
        std::regex repl("\\s+");
        osl::log(osl::debug, "parser: cur line: %s", line.c_str());

        if (line.find("Len") != std::string::npos) {
            std::regex_search(line, match, reg);
            osl::log(osl::debug, "parser: found msg");
            len = std::regex_replace(match.str(), repl, "");
        }
        
        if (line.find("Msg") != std::string::npos) {
            std::regex_search(line, match, reg);
            osl::log(osl::debug, "parser: found msg");
            msg = std::regex_replace(match.str(), repl, "");
        }
        
        if (line.find("MD") != std::string::npos) {
            std::regex_search(line, match, reg);
            dgst = std::regex_replace(match.str(), repl, "");
            osl::log(osl::debug, "parser: found md");

            auto vec = std::make_shared<shavs_vector>(len, msg, dgst);
            test->add_vector(vec);
        }
    }

    _tests.push_back(test);
}
