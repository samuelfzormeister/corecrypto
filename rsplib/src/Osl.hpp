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

#ifndef __RSPLIB_OSL_HPP__
#define __RSPLIB_OSL_HPP__

#include <cstdarg>
#include <string>

namespace Rsp {
    namespace Osl {
        enum LogLevel {
            Error,
            Warning,
            Info,
            Debug,
        };

        class OslService {
            public:
            static OslService *_pInstance;

            virtual void abortWithReason(std::string reason) = 0;

            virtual void logv(const char *component, Osl::LogLevel level, const char *format, va_list args) = 0;
        };

        inline void AbortWithReason(std::string reason) {
            return OslService::_pInstance->abortWithReason(reason);
        }

        inline void Log(const char *component, Osl::LogLevel level, const char *format, ...) {
            va_list list;
            va_start(list, format);
            OslService::_pInstance->logv(component, level, format, list);
            va_end(list);
            return;
        }
    }
}

#endif /* __RSPLIB_OSL_HPP__ */
