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

#include <iostream>
#include <string>

//
// cccryptotool hash -algorithm sha-256 -data <hex data>
// cccryptotool hash -algorithm sha-256 -f /path/to/file
// cccryptotool encrypt -algorithm aes-cbc -key <key> -iv <iv> -data <hex data>
// cccryptotool encrypt -algorithm aes-cbc -key <key> -iv <iv> -f /path/to/file -o /path/to/output
//

typedef enum {
    HASH,
    ENCRYPT,
    DECRYPT,
} ccctool_mode;

static std::string filepath;
static std::string outpath;
static std::string iv;
static ccctool_mode operation;
static std::string algorithm;
static std::string key;

void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "-f") {
            filepath = argv[i+1];
        } else if (str == "-o") {
            outpath = argv[i+1];
        } else if (str == "encrypt") {
            operation = ENCRYPT;
        } else if (str == "decrypt") {
            operation = DECRYPT;
        } else if (str == "hash") {
            operation = HASH;
        }
    }
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    return 0;
}
