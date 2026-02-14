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

#ifndef __RSPLIB_BASE__
#define __RSPLIB_BASE__

#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

/* Make this clean in case this gets reused anywhere. */
namespace corecrypto {

    namespace rsplib {
        //
        // the overarching test - composed of vectors.
        //
        class base_test {
            public:
            base_test(const std::string &name);

            enum {
                base,
                aesvs,
            };

            //
            // virtual interfaces.
            //
            virtual void write_to_stream(std::stringstream &stream);

            const std::string &get_name(void) { return _name; }

            virtual uint32_t get_test_kind() {
                return base;
            }

            protected:
            std::string _name;
        };

        class base_vector {
            public:
            base_vector(const std::string &input, const std::string &expected_output);

            public:
            virtual const std::string &get_input(void)  { return _input; }
            virtual const std::string &get_expected_output(void) { return _expected_output; }

            private:
            std::string _input;
            std::string _expected_output;
        };

        class parser {
            //
            // We use stringstream for simplicty.
            //
            public:
            parser(const std::string &basename, std::stringstream &stream);

            const std::vector<std::shared_ptr<base_test>> &get_tests(void);

            void parse_aesvs(std::stringstream &stream, bool ecb);

            void write_tests_to_stream(std::stringstream &stream);

            void write_tests_to_directory(std::filesystem::path &path);

            void write_header(std::stringstream &stream);

            private:
            std::string _basename;
            std::vector<std::shared_ptr<base_test>> _tests;   // we allocate a pointer here
        };
    }
};

#endif /* __RSPLIB_BASE__ */
