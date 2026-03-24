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

#include <memory>
#include <rsplib/osl.hpp>
#include <rsplib/aesvs.hpp>
#include <sstream>

using namespace corecrypto::rsplib;

aesvs_test::aesvs_test(const std::string &name, mode mode) : base_test(name)
{
    osl::log(osl::log_level::debug, "creating an aesvs test obj... (%s)", name.c_str());
    _mode = mode;
}

void aesvs_test::add_vector(std::shared_ptr<aesvs_vector> vector) {
    osl::log(osl::log_level::debug, "adding a vector to the table");
    osl::log(osl::log_level::debug, "key: %s", vector->get_key().c_str());
    osl::log(osl::log_level::debug, "iv: %s", vector->get_iv().c_str());
    osl::log(osl::log_level::debug, "plaintext: %s", vector->get_input().c_str());
    osl::log(osl::log_level::debug, "ciphertext: %s", vector->get_expected_output().c_str());

    _testVectors.push_back(vector);
}

/*
 struct ccmode_test_vector vecs[] = {
     {
         CCTEST_ATTRS_NONE,  // attrs
                             // key
                             // key length
                             // iv
                             // iv length
                             // text length
                             // pt
                             // ct
                             // aad
                             // aad length
     } 
 };
 */

void aesvs_test::write_to_stream(std::stringstream &stream)
{
    //
    // Write header
    //
    base_test::write_to_stream(stream);

    //stream << "struct ccmode_test_vector " << _name << "[] = {" << std::endl;

    for (std::shared_ptr<aesvs_vector> vec : _testVectors) {
        stream << "    {" << std::endl;
        stream << "        CCTEST_ATTRS_NONE," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_key());
        stream << "," << std::endl;
        stream << "        " << vec->get_key().length() / 2;
        stream << "," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_iv());
        stream << "," << std::endl;
        stream << "        " << vec->get_iv().length() / 2;
        stream << "," << std::endl;
        stream << "        " << vec->get_input().length() / 2;
        stream << "," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_input());
        stream << "," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_expected_output());
        stream << "," << std::endl;
        stream << "        0," << std::endl;
        stream << "        NULL," << std::endl;
        stream << "    }," << std::endl;
    }

    //stream << "};" << std::endl;
}
