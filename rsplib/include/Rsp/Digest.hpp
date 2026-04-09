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

#ifndef __RSPLIB_DIGEST_HPP__
#define __RSPLIB_DIGEST_HPP__

#include "Core.hpp"

namespace Rsp {
    namespace Digest {
        enum DigestAlgorithm {
            // --- FIPS 180 ALGORITHMS BEGIN --- //
            SHA1,
            SHA224,
            SHA256,
            SHA384,
            SHA512,
            SHA512_224,
            SHA512_256,
            // --- FIPS 180 ALGORITHMS END --- //

            // --- FIPS 202 ALGORITHMS BEGIN --- //
            SHA3_224,
            SHA3_256,
            SHA3_384,
            SHA3_512,
            // --- FIPS 202 ALGORITHMS END --- //
        };

        class Vector : public Core::Vector {
            public:
            Vector(const std::string &length, 
                   const std::string &msg, 
                   const std::string &digest);

            const std::string &getBitLength(void);

            protected:
            std::string m_bitLength;
        };

        class Test : public Core::Test {
            public:
            Test(DigestAlgorithm algorithm, const std::string &name);
        };
    }
}

#endif /* __RSPLIB_DIGEST_HPP__ */

