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

#ifndef __RSPLIB_AESVS__
#define __RSPLIB_AESVS__

#include <rsplib/base.hpp>

namespace corecrypto {

    namespace rsplib {

        using aesvs_vector = class block_cipher_vector;

        //
        // AESVS vector.
        //
        class aesvs_test : public base_test {
            public:
            enum mode {
                ecb,
                cbc,
                cfb1,           // unused by corecrypto. we only do CFB8 and CFB128 for AES.
                cfb8,
                cfb128,
                ofb,
                xts,            // technically falls under XTS-VS but we reuse AESVS for handling XTS.
            };

            aesvs_test(const std::string &name, mode mode);

            void add_vector(std::shared_ptr<aesvs_vector>);

            virtual void write_to_stream(std::stringstream &stream) override;

            mode get_mode(void) { return _mode; }

            protected:
            std::vector<std::shared_ptr<aesvs_vector>> _testVectors;
            std::string _name;
            mode _mode;
        };

    }

}

#endif /* __RSPLIB_AESVS__ */