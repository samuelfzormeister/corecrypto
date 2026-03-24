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

#include <rsplib/cipher.hpp>
#include <rsplib/file.hpp>
#include <vector>
#include <regex>

#include "FileInternal.hpp"
#include "osl.hpp"

using namespace Rsp;

#define COMPONENT "AESVS"


#define TRACE_BEGIN Osl::Log( COMPONENT , Osl::Debug , "%s >>", __FUNCTION__)
#define TRACE_END Osl::Log( COMPONENT , Osl::Debug , "%s <<", __FUNCTION__)

#define LOG(lvl, x...) Osl::Log( COMPONENT , lvl , ##x )


std::vector<Foundation::Test> AesVsParser::parse(const std::string &filename, std::stringstream &file)
{
    Cipher::CipherMode mode;
    std::vector<Foundation::Test> tests;
    std::string line;
    std::string key;
    std::string iv;
    std::string plaintext;
    std::string ciphertext;
    bool curEnc;

    if (m_fileDetectionLine.find("ECB") != std::string::npos) {
        mode = Cipher::ECB;
    } else if (m_fileDetectionLine.find("CBC") != std::string::npos) {
        mode = Cipher::CBC;
    } else if (m_fileDetectionLine.find("CFB128") != std::string::npos) {
        mode = Cipher::CFB;
    } else if (m_fileDetectionLine.find("CFB8") != std::string::npos) {
        mode = Cipher::CFB8;
    } else if (m_fileDetectionLine.find("OFB") != std::string::npos) {
        mode = Cipher::OFB;
    } else {
        Osl::AbortWithReason("Unknown cipher mode for AES-VS.");
    }

    Cipher::Test encryptTest(Cipher::Test::Encrypt, mode, filename + "_encrypt");
    Cipher::Test decryptTest(Cipher::Test::Decrypt, mode, filename + "_decrypt");

     while (std::getline(file, line)) {
        std::smatch match;
        std::regex reg("(\\S+)\\s*$");
        std::regex repl("\\s+");
        LOG(Osl::Debug, "parser: cur line: %s", line.c_str());
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
            LOG(Osl::Debug, "parser: found key");
            key = std::regex_replace(match.str(), repl, "");
        }
        
        if (line.find("IV") != std::string::npos) {
            std::regex_search(line, match, reg);
            iv = std::regex_replace(match.str(), repl, "");
            LOG(Osl::Debug, "parser: found iv");
        }

        if (curEnc) {
            if (line.find("PLAINTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                LOG(Osl::Debug, "parser: found pt");
                plaintext = std::regex_replace(match.str(), repl, "");
                LOG(Osl::Debug, "parser: %s", plaintext.c_str());
            }

            if (line.find("CIPHERTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                LOG(Osl::Debug, "parser: found ct");
                ciphertext = std::regex_replace(match.str(), repl, "");
                LOG(Osl::Debug, "parser: %s", ciphertext.c_str());
                encryptTest.addVector(plaintext, ciphertext, key, iv);
            }
        } else {
            if (line.find("CIPHERTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                LOG(Osl::Debug, "parser: found ct");
                ciphertext = std::regex_replace(match.str(), repl, "");
                LOG(Osl::Debug, "parser: %s", ciphertext.c_str());
            }

            if (line.find("PLAINTEXT") != std::string::npos) {
                std::regex_search(line, match, reg);
                LOG(Osl::Debug, "parser: found pt");
                plaintext = std::regex_replace(match.str(), repl, "");
                LOG(Osl::Debug, "parser: %s", plaintext.c_str());
                decryptTest.addVector(ciphertext, plaintext, key, iv);
            }
        }
    }

    tests.push_back(encryptTest);
    tests.push_back(decryptTest);

    return tests;
}

