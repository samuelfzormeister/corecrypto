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

#ifndef __RSPLIB_PARSER__
#define __RSPLIB_PARSER__

#include <rsplib/base.hpp>
#include <rsplib/aesvs.hpp>
#include <rsplib/shavs.hpp>
#include <rsplib/xtsvs.hpp>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

/* Make this clean in case this gets reused anywhere. */
namespace corecrypto {

    namespace rsplib {

        class parser {
            //
            // We use stringstream for simplicty.
            //
            public:
            parser(const std::string &basename, std::stringstream &stream);

            const std::vector<std::shared_ptr<base_test>> &get_tests(void) { return _tests; }

            void write_tests_to_stream(std::stringstream &stream);

            void write_tests_to_directory(std::filesystem::path &path);

            private:
            void write_header(std::stringstream &stream);

            private:
            void parse_aesvs(std::stringstream &stream, aesvs_test::mode mode);
            void parse_xtsvs(std::stringstream &stream);
            void parse_shavs(std::stringstream &stream, shavs_test::variant variant);

            private:
            std::string _basename;
            std::vector<std::shared_ptr<base_test>> _tests;   // we allocate a pointer here
        };
    }
};

#endif /* __RSPLIB_PARSER__ */
