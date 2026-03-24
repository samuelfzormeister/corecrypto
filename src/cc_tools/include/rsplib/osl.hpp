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

//
// !!! INTERNAL !!!
//

#ifndef __RSPLIB_OSL__
#define __RSPLIB_OSL__

#include <sstream>

//
// corecrypto C++ OS Layer
//

namespace corecrypto {

    namespace osl {
        enum log_level {
            error,
            warning,
            debug,
            info,
        };

        void log(log_level level, const char *fmt, ...);

        void abort(const char *fmt, ...);
    }

    namespace util {
        void write_hex_string(std::stringstream &stream, const std::string &string);
    }

}

#endif
