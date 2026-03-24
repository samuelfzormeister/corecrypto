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

#ifndef __RSPLIB_FOUNDATION_HPP__
#define __RSPLIB_FOUNDATION_HPP__

#include <sstream>
#include <string>
#include <vector>

//
// RspLib is an inherently corecrypto project, However I do wonder if it should be
// relocated outside of the corecrypto project as a tool for development.
//
// Considering the recent TestDriver abstractions, it's likely to be portable to other
// frameworks and libraries.
//
// Eg: We can test CommonCrypto from here (although, CommonCrypto is driven by corecrypto, so...)
//

namespace Rsp {
    namespace Foundation {

        class Vector {
            public:
            Vector(const std::string &in, const std::string &out);

            const std::string &getInput(void) { return  m_in; }

            const std::string &getOutput(void) { return  m_out; }

            protected:
            std::string m_in;
            std::string m_out;
        };

        enum VectorWriterFormat {
            Invalid,
            CoreCrypto,
        };
    
        class VectorWriter {
            public:
            VectorWriter(VectorWriterFormat fmt, const std::vector<Vector> &vector);

            void writeHeader(std::stringstream &stream);

            //
            // Implemented by subclasses.
            //
            virtual void writeVectors(std::stringstream &stream) = 0;

            protected:
            VectorWriterFormat m_fmt;
            std::vector<Vector> m_vectors;
        };

        class Test {
            public:
            Test(const std::string &name);

            enum Driver {
                Invalid,
                CoreCrypto,
            };

            //
            // Interfaces for on-the-fly testing.
            //
            virtual int conductTest(Driver driver) = 0;
    
            const std::vector<Vector> &getVectors(void) { return m_vectors; }

            protected:
            friend class File;

            protected:
            std::string m_name;
            std::vector<Vector> m_vectors;
        };

        class TestDriver {
            public:
            virtual int runVector(Vector vec) = 0;
        };
    }
}

#endif /* __RSPLIB_FOUNDATION_HPP__ */
