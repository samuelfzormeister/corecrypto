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

        class aesvs_vector : public base_vector {
            public:
            aesvs_vector(const std::string &key,
                         const std::string &iv,
                         const std::string &plaintext,
                         const std::string &ciphertext);

            virtual const std::string &get_key(void) { return _key; }

            virtual const std::string &get_iv(void) { return _iv; }

            protected:
            std::string _key;
            std::string _iv;
        };

        //
        // AESVS vector.
        //
        class aesvs_test : public base_test {
            public:
            enum {
                ecb,
                cbc,
            };

            aesvs_test(const std::string &name);

            void add_vector(std::shared_ptr<aesvs_vector>);

            virtual void write_to_stream(std::stringstream &stream) override;

            private:
            std::vector<std::shared_ptr<aesvs_vector>> _testVectors;
            std::string name;
        };

    }

}

#endif /* __RSPLIB_AESVS__ */