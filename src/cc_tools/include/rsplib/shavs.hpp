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

#ifndef __RSPLIB_SHAVS__
#define __RSPLIB_SHAVS__

#include <rsplib/base.hpp>

namespace corecrypto {

    namespace rsplib {
        //
        // SHAVS vector.
        //
        class shavs_vector : public base_vector {
            public:
            shavs_vector(const std::string &len,
                         const std::string &msg,
                         const std::string &md);
        
            const std::string &get_length_field() { return _length; }
        
            private:
            std::string _length;
        };
    
        class shavs_test : public base_test {
            public:

            enum variant {
                sha1,
                sha224,
                sha256,
                sha384,
                sha512,
                sha512_224,
                sha512_256,
                sha3_224,
                sha3_256,
                sha3_384,
                sha3_512,
            };

            shavs_test(const std::string &name, variant variant);

            void add_vector(std::shared_ptr<shavs_vector>);

            virtual void write_to_stream(std::stringstream &stream) override;

            private:
            std::vector<std::shared_ptr<shavs_vector>> _testVectors;
            variant _varient;
        };

    }

}

#endif /* __RSPLIB_SHAVS__ */
