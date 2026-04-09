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

#include <corecrypto/cc_absolute_time.h>

#include <corecrypto/cc_debug.h>

#if CC_DARWIN

#include <mach/mach_time.h>

uint64_t cc_absolute_time(void)
{
    return mach_absolute_time();
}

uint64_t cc_absolute_time_to_msec(uint64_t time)
{
    struct mach_timebase_info in;

    mach_timebase_info(&in);

    return (uint64_t)(((time * in.numer) / in.denom)) / NSEC_PER_MSEC;
}

#elif CC_LINUX

#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC  1000000000
#define NSEC_PER_MSEC 1000000

/*
static pthread_once_t clock_init_once;
static struct timespec clock_resolution;

void __linux_clock_init(void)
{
    clock_getres(CLOCK_MONOTONIC_RAW, &clock_resolution);
}
*/

uint64_t cc_absolute_time(void)
{
    struct timespec time;

    //pthread_once(clock_init_once, &__linux_clock_init);

    clock_gettime(CLOCK_MONOTONIC_RAW, &time);

    return (time.tv_sec * NSEC_PER_SEC) + time.tv_nsec;
}

uint64_t cc_absolute_time_to_msec(uint64_t abs)
{
    //pthread_once(clock_init_once, &__linux_clock_init);

    return abs / NSEC_PER_MSEC;
}

#elif CC_WINDOWS && !CC_DARWINBOOT

#include <stdbool.h>
#include <windows.h>

static uint64_t abs_freq = 0;

uint64_t cc_absolute_time(void)
{
    LARGE_INTEGER pc;

    QueryPerformanceCounter(&pc);

    return (uint64_t)pc.QuadPart;
}

uint64_t cc_absolute_time_to_msec(uint64_t abs)
{
    LARGE_INTEGER pf;

    // only call QPF once. we want low latency.
    if (abs_freq == 0) {
        QueryPerformanceFrequency(&pf);
        abs_freq = pf.QuadPart;
    }

    return (uint64_t)((abs) * 1000 / abs_freq);
}

#endif
