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

#include <corecrypto/cc_lock.h>

#if CC_PTHREAD_LOCK

#include <pthread.h>

void cc_lock_mutex_init(cc_lock_mutex_t *lock, const char *group_name)
{
    pthread_mutex_init(&lock->mtx, NULL);
}

void cc_lock_mutex_lock(cc_lock_mutex_t *lock)
{
    pthread_mutex_lock(&lock->mtx);
}

void cc_lock_mutex_unlock(cc_lock_mutex_t *lock)
{
    pthread_mutex_unlock(&lock->mtx);
}

bool cc_lock_mutex_try_lock(cc_lock_mutex_t *lock)
{
    return pthread_mutex_trylock(&lock->mtx);
}

#elif CC_DARWIN_LOCK

#include <os/lock.h>

void cc_lock_mutex_init(cc_lock_mutex_t *lock, const char *group_name)
{
    lock->mtx = OS_UNFAIR_LOCK_INIT;
}

void cc_lock_mutex_lock(cc_lock_mutex_t *lock)
{
    os_unfair_lock_lock(&lock->mtx);
}

void cc_lock_mutex_unlock(cc_lock_mutex_t *lock)
{
    os_unfair_lock_unlock(&lock->mtx);
}

bool cc_lock_mutex_try_lock(cc_lock_mutex_t *lock)
{
    return os_unfair_lock_trylock(&lock->mtx);
}

#elif CC_XNU_LOCK

#include <kern/locks.h>

//
// easiest way to detect a public SDK.
//
#if !defined(GATE_HANDOFF)
extern boolean_t lck_mtx_try_lock(lck_mtx_t *lck);
#endif

void cc_lock_mutex_init(cc_lock_mutex_t *lock, const char *group_name)
{
    lock->grp = lck_grp_alloc_init(group_name, NULL);
    lock->mtx = lck_mtx_alloc_init(lock->grp, NULL);
}

void cc_lock_mutex_lock(cc_lock_mutex_t *lock)
{
    lck_mtx_lock(lock->mtx);
}

void cc_lock_mutex_unlock(cc_lock_mutex_t *lock)
{
    lck_mtx_unlock(lock->mtx);
}

bool cc_lock_mutex_try_lock(cc_lock_mutex_t *lock)
{
    return lck_mtx_try_lock(lock->mtx);
}

#endif
