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

#include <rsplib/cipher.hpp>

#include "Osl.hpp"

using namespace Rsp::Cipher;

#define LOG(lvl, x...) Osl::Log("CIPHER", lvl , ##x )

Vector::Vector(const std::string &in, 
               const std::string &out,
               const std::string &key, 
               const std::string &iv) : Foundation::Vector(in, out), m_key(key), m_iv(iv)
{
    LOG(Osl::Debug, "creating Cipher::Vector");
}
