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

#ifndef __RSPLIB_TDES__
#define __RSPLIB_TDES__

#include <rsplib/base.hpp>

namespace corecrypto {

    namespace rsplib {

        class tdes_vector : public block_cipher_vector {
            tdes_vector(const std::string &key,
                         const std::string &iv,
                         const std::string &plaintext,
                         const std::string &ciphertext);
        };

    }

}

#endif /* __RSPLIB_AESVS__ */
