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

#include <string>
#include "lib/RSPParser.hpp"

using namespace CoreCrypto::RSP;

/* rsp2header hash -f <path/to/file> -o <path/to/out> */
/* rsp2header cipher -m cbc -f <path/to/vectors>.rsp -o <path/to/out>.h */

/* usually test vectors contain a DECRYPT and ENCRYPT tag in sections. it is up to RSPParser to handle this. */

const char *gRSPPath;
const char *gOutputPath;

Test::Operation gOp = Test::Operation::Hash; /* keep it like this for now */

void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "hash") {
            /* initialise parser context */
            gOp = Test::Operation::Hash;
        } else if (str == "-f") {
            gRSPPath = str.c_str();
        } else if (str == "-o") {
            gOutputPath = str.c_str();
        }
    }
}

int main(int argc, const char *argv[]) {

}
