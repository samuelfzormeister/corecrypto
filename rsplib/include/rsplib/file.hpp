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

#ifndef __RSPLIB_FILE_HPP__
#define __RSPLIB_FILE_HPP__

#include <memory>
#include "foundation.hpp"

namespace Rsp {

    /*!
     * @class File
     *
     * Do not create this class directly. Call Rsp::CreateFileFromStream
     */
    class File {
        public:
        File(const std::string &filename,
             std::stringstream &file, 
             const std::string &fileDetectionLine);

        const std::vector<Foundation::Test> &getTests(void) { return m_tests; }

        protected:
        enum FileKind {
            Invalid,
            AesVs,
            ShaVs,
            XtsVs,
            GcmVs,
            CcmVs,
            CmacVs,
            DrbgVs,

            // --- Don't even bother with HMACVS, the RSP files don't define algorithms. --- //
        };

        protected:
        std::vector<Foundation::Test> m_tests;
        std::string m_fileDetectionLine;
        std::string m_filename;
    };

    std::shared_ptr<File> CreateFileFromStream(const std::stringstream &stream);
}

#endif /* __RSPLIB_FILE_HPP__ */
