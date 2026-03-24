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

#ifndef __RSPLIB_CIPHER_HPP__
#define __RSPLIB_CIPHER_HPP__

#include "foundation.hpp"

namespace Rsp {

    namespace Cipher {

        // ccm and gcm are in Rsp::Aead
        enum CipherMode {
            ECB,

            // Cipher Block Chain mode.
            CBC,

            // Equivalent to CFB128 for AES.
            CFB,

            // CFB8
            CFB8,

            // Output Feedback mode.
            OFB,

            // --- CIPHER-SPECIFIC MODES BEGIN HERE --- //
            XTS,
            // ---    CIPHER-SPECIFIC MODES END     --- //
        };

        enum CipherAlgorithm {
            AES,
            TripleDES,
        };

        class Vector : public Foundation::Vector {
            public:
            Vector(const std::string &in, const std::string &out,
                   const std::string &key, const std::string &iv);

            const std::string &getKey(void) { return  m_key; }

            const std::string &getIV(void) { return  m_iv; }

            protected:
            std::string m_key;
            std::string m_iv;
        };

        class Test : public Foundation::Test {
            public:
            enum Operation {
                Encrypt,
                Decrypt
            };

            Test(Operation op, CipherMode mode, const std::string &name);

            virtual void addVector(const std::string &in, 
                                   const std::string &out,
                                   const std::string &key, 
                                   const std::string &iv);

            virtual int conductTest(Driver driver) override;

            protected:
            CipherMode m_mode;
        };
    
    }

}

#endif /* __RSPLIB_CIPHER_HPP__ */
