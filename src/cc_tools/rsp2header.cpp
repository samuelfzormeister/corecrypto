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

#include <rsplib/osl.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include <filesystem>
#include <rsplib/parser.hpp>

using namespace corecrypto;

/* rsp2header hash -f <path/to/file> -o <path/to/out> */
/* rsp2header -f <path/to/vectors>.rsp -o <path/to/out>.h */

static std::string path;
static std::string output_path;
static bool split_tests = false;

void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "-f") {
            path = argv[i+1];
        } else if (str == "-o") {
            output_path = argv[i+1];
        } else if (str == "-split") {
            split_tests = true;
        }
    }
}

int main(int argc, const char *argv[]) {
    parse_args(argc, argv);

    osl::log(osl::debug, "r2h: enter");
    osl::log(osl::debug, "r2h: %s", path.c_str());

    std::fstream stream(path);
    std::stringstream ss;
    ss << stream.rdbuf();
    stream.close();

    std::filesystem::path fspath = path;
    std::filesystem::path name = fspath.stem();
    std::string basename = name.u8string();

    rsplib::parser parser(basename, ss);

    std::stringstream out_stream;

    if (split_tests) {
        osl::log(osl::debug, "r2h: split");
        std::filesystem::path opath = output_path;
        parser.write_tests_to_directory(opath);
        return 0;
    } else {
        parser.write_tests_to_stream(out_stream);
    }

    std::fstream outstream;
    outstream.open(output_path, std::fstream::out);
    outstream << out_stream.str();
    outstream.close();
}
