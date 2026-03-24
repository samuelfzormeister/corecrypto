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

#ifndef __RSPLIB_TESTDRIVER_HPP__
#define __RSPLIB_TESTDRIVER_HPP__

#include <rsplib/aead.hpp>
#include <rsplib/cipher.hpp>
#include <rsplib/digest.hpp>

namespace Rsp {
    class TestContext {
        TestContext(const std::string &name);
    };

    namespace Digest {
        // --- We need an algorithm for the test --- ///
        class TestContext : public Rsp::TestContext {
            TestContext(DigestAlgorithm mode, const std::string &name);

            protected:
            DigestAlgorithm m_digestAlgorithm;
        };
    }

    namespace Cipher {
        // --- We need a mode for the Cipher --- ///
        class TestContext : public Rsp::TestContext {
            TestContext(CipherMode mode, const std::string &name);

            protected:
            CipherMode m_cipherMode;
        };
    }

    namespace Aead {
        // --- We need a mode for the Cipher --- ///
        class TestContext : public Rsp::TestContext {
            TestContext(AeadMode mode, const std::string &name);

            protected:
            AeadMode m_cipherMode;
        };
    }
}

#endif /* __RSPLIB_TESTDRIVER_HPP__ */
