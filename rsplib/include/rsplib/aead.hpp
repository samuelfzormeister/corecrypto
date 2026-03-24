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

#ifndef __RSPLIB_AEAD_HPP__
#define __RSPLIB_AEAD_HPP__

#include "cipher.hpp"

namespace Rsp {

    namespace Aead {

        enum AeadMode {
            // Galois Counter Mode
            GCM,

            // CBC Counter Mode
            CCM,
        };

        static inline std::string GetModeName(AeadMode mode) {
            switch (mode) {
                case Aead::GCM:
                    return "Galois Counter Mode";
                case Aead::CCM:
                    return "CBC Counter Mode";
                default:
                    return "Invalid AEAD Mode";
            }
        }

        class Vector : public Cipher::Vector {
            public:
            Vector(const std::string &in, const std::string &out,
                   const std::string &key, const std::string &iv,
                   const std::string &tag, bool willFail);

            // --- The authentication of GCM is called a 'tag'. --- //
            const std::string &getTag(void) { return  m_tag; }

            // --- For consistency, CCM outputs a 'MAC'. We'll use the m_tag field internally. --- //
            const std::string &getMAC(void) { return m_tag; }

            // --- The additional data is 'AAD', --- //
            const std::string &getAAD(void) { return  m_aad; }

            // --- GCM VS and CCM VS both have indicators as to whether verifictaion will fail --- //
            bool willFail(void) { return m_willFail; }

            protected:
            std::string m_tag;
            std::string m_aad;
            bool m_willFail;
        };

        // --- We inherit from Cipher::Test so we can reuse the driver backend. --- //
        class Test : public Cipher::Test {
            public:
            Test(AeadMode mode, const std::string &name);

            virtual void addVector(const std::string &in,
                                   const std::string &out,
                                   const std::string &key, 
                                   const std::string &iv,
                                   const std::string &tag,
                                   bool willFail);

            protected:
            AeadMode m_aeadMode;
        };
    }
}

#endif /* __RSPLIB_AEAD_HPP__ */
