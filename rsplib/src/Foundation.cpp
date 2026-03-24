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

#include <rsplib/foundation.hpp>

#include "osl.hpp"

#define TRACE_BEGIN Osl::Log("FOUNDATION", Osl::Debug , "%s >>", __FUNCTION__)
#define TRACE_END Osl::Log("FOUNDATION", Osl::Debug , "%s <<", __FUNCTION__)

#define LOG(lvl, x...) Osl::Log("FOUNDATION", lvl , ##x )

using namespace Rsp::Foundation;

Vector::Vector(const std::string &in, const std::string &out) : m_in(in), m_out(out)
{
    TRACE_BEGIN;

    // --- do this shit --- //

    TRACE_END;
}

Test::Test(const std::string &name) : m_name(name)
{
    LOG(Osl::Debug, "creating foundation test");
}
