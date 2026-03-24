/*
 * Copyright (C) 2025-2026 The PureDarwin Project, All rights reserved.
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

#ifndef __RSPLIB_BASE__
#define __RSPLIB_BASE__

#include <sstream>
#include <string>
#include <vector>

/* Make this clean in case this gets reused anywhere. */
namespace corecrypto {

    namespace rsplib {
        //
        // the overarching test - composed of vectors.
        //
        class base_test {
            public:
            base_test(const std::string &name);

            enum {
                base,
                aesvs,
                shavs,
            };

            //
            // virtual interfaces.
            //
            virtual void write_to_stream(std::stringstream &stream);

            const std::string &get_name(void) { return _name; }

            virtual uint32_t get_kind() {
                return base;
            }

            protected:
            std::string _name;
        };

        // base class 
        class base_vector {
            public:
            base_vector(const std::string &input, const std::string &expected_output);

            public:
            virtual const std::string &get_input(void)  { return _input; }
            virtual const std::string &get_expected_output(void) { return _expected_output; }

            private:
            std::string _input;
            std::string _expected_output;
        };

        class block_cipher_vector : public base_vector {
            public:
            block_cipher_vector(const std::string &key,
                         const std::string &iv,
                         const std::string &plaintext,
                         const std::string &ciphertext);

            virtual const std::string &get_key(void) { return _key; }

            virtual const std::string &get_iv(void) { return _iv; }

            protected:
            std::string _key;
            std::string _iv;
        };

        class aead_vector : public block_cipher_vector {
            public:
            aead_vector(const std::string &key,
                        const std::string &iv,
                        const std::string &plaintext,
                        const std::string &ciphertext,
                        const std::string &tag);

            protected:
            std::string _tag;
        };
    }
};

#endif /* __RSPLIB_BASE__ */
