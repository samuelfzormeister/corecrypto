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

#include <corecrypto/cc_config.h>
#include <string>

#include "osl.hpp"

using namespace Rsp;

static const char *__levels[] = {
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG"
};

#if CC_DARWIN

Osl::OslService *Osl::OslService::_pInstance = NULL;

class OslServiceDarwin : public Osl::OslService {
    public:
    OslServiceDarwin();

    virtual void abortWithReason(std::string reason) override;
    virtual void logv(const char *component, Osl::LogLevel level, const char *format, va_list args) override;
};

static OslServiceDarwin _osl;

OslServiceDarwin::OslServiceDarwin()
{
    Osl::OslService::_pInstance = this;
    Osl::Log("OSL", Osl::Debug, "OSL has initialized.");
}

void OslServiceDarwin::abortWithReason(std::string reason)
{
    std::fprintf(stderr, "%s\n", reason.c_str());
    abort();
}

void OslServiceDarwin::logv(const char *component, Osl::LogLevel level, const char *format, va_list args)
{
    std::printf("[%s][%s]:", component, __levels[level]);
    std::vprintf(format, args);
    std::printf("\n");
}

#elif CC_WINDOWS

Osl::OslService *Osl::OslService::_pInstance = NULL;

class OslServiceWindows : public Osl::OslService {
    public:
    OslServiceWindows();

    virtual void abortWithReason(std::string reason) override;
    virtual void logv(const char *component, Osl::LogLevel level, const char *format, va_list args) override;
};

static OslServiceWindows _osl;

OslServiceWindows::OslServiceWindows()
{
    Osl::OslService::_pInstance = this;
    Osl::Log("OSL", Osl::Debug, "OSL has initialized.");
}

void OslServiceWindows::abortWithReason(std::string reason)
{
    std::fprintf(stderr, "%s\n", reason.c_str());
    abort();
}

void OslServiceWindows::logv(const char *component, Osl::LogLevel level, const char *format, va_list args)
{
    std::printf("[%s][%s]:", component, __levels[level]);
    std::vprintf(format, args);
    std::printf("\n");
}

#endif

