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

#ifndef __RSPLIB_FILEINTERNAL_HPP__
#define __RSPLIB_FILEINTERNAL_HPP__

#include <Rsp/File.hpp>
#include <sstream>

namespace Rsp {
    class FileParser {
        public:
        FileParser(const std::string &detectedLine);

        virtual std::vector<Core::Test> parse(const std::string &filename, std::stringstream &file) = 0;

        protected:
        std::string m_fileDetectionLine;
    };

    class AesVsParser : public FileParser {
        public:
        AesVsParser(const std::string &detectedLine);

        virtual std::vector<Core::Test> parse(const std::string &filename, std::stringstream &file) override;
    };

    class XtsVsParser : public FileParser {
        public:
        XtsVsParser(const std::string &detectedLine);

        virtual std::vector<Core::Test> parse(const std::string &filename, std::stringstream &file) override;
    };

    class ShaVsParser : public FileParser {
        public:
        ShaVsParser(const std::string &detectedLine);

        virtual std::vector<Core::Test> parse(const std::string &filename, std::stringstream &file) override;
    };
}

#endif /* __RSPLIB_FILEINTERNAL_HPP__ */
