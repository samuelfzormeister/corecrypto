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
#include <rsplib/shavs.hpp>
#include <rsplib/osl.hpp>

using namespace corecrypto::rsplib;
using namespace corecrypto;

shavs_test::shavs_test(const std::string &name) : base_test(name)
{
    //
    // do nothing.
    //
}

void shavs_test::add_vector(std::shared_ptr<base_vector> vec)
{
    _testVectors.push_back(vec);
}

/*
 typedef struct ccdigest_test_vector {
    uint32_t attrs;

    const char *message;
    size_t msg_len;
    const char *expected_digest;
 } ccdigest_test_vector;
 */

void shavs_test::write_to_stream(std::stringstream &stream)
{
    for (std::shared_ptr<base_vector> vec : _testVectors) {
        stream << "    {" << std::endl;
        stream << "        CCTEST_ATTRS_NONE," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_input());
        stream << "," << std::endl;
        stream << "        " << vec->get_input().length() / 2;
        stream << "," << std::endl;
        stream << "        ";
        util::write_hex_string(stream, vec->get_expected_output());
        stream << std::endl;
        stream << "    }," << std::endl;
    }
}
