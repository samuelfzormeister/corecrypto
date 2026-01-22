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

#ifndef _CORECRYPTO_CC_LOCK_H_
#define _CORECRYPTO_CC_LOCK_H_

#include <stdbool.h>
#include <corecrypto/cc_config.h>

#define CC_PTHREAD_LOCK     CC_LINUX
#define CC_DARWIN_LOCK      CC_DARWIN
#define CC_XNU_LOCK         CC_KERNEL

#if CC_PTHREAD_LOCK

#include <pthread.h>

typedef struct {
    pthread_mutex_t mtx;
} cc_lock_mutex_t;

#elif CC_XNU_LOCK

#include <kern/locks.h>

typedef struct {
    lck_grp_t *grp;
    lck_mtx_t *mtx;
} cc_lock_mutex_t;

#elif CC_DARWIN_LOCK

#include <os/lock.h>

typedef struct {
    os_unfair_lock mtx;
} cc_lock_mutex_t;

#else
#error "cc_lock has not been ported to this platform"
#endif

//
// lock groups are really only necessary on the KEC build of corecrypto
//
void cc_lock_mutex_init(cc_lock_mutex_t *lock, const char *group_name);

void cc_lock_mutex_lock(cc_lock_mutex_t *lock);

void cc_lock_mutex_unlock(cc_lock_mutex_t *lock);

bool cc_lock_mutex_try_lock(cc_lock_mutex_t *lock);

#endif /* _CORECRYPTO_CC_LOCK_H_ */
