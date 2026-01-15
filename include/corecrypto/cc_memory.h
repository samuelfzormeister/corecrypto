/*
 * Copyright (C) 2025 The PureDarwin Project, All rights reserved.
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

#ifndef _CORECRYPTO_CC_MEMORY_H_
#define _CORECRYPTO_CC_MEMORY_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccn.h>

/* Workspace related macros go here. */

#define CC_WORKSPACE_STACK_DECL_N(ws, n) \
            cc_unit ws##_buf[ccn_sizeof_n(n)]; \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = (cc_unit *)&ws##_buf; \
            ws->end = ws->start + ccn_sizeof_n(n); \

#define CC_WORKSPACE_STACK_FREE_N(ws, n) \
            ccn_clear(n, ws->start); \
            ws->start = NULL; \
            ws->end = NULL; \

#define CC_WORKSPACE_STACK_DECL(ws, size) \
            uint8_t ws##_buf[size]; \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = (cc_unit *)&ws##_buf; \
            ws->end = ws->start + size; \

#define CC_WORKSPACE_STACK_FREE(ws, size) \
            cc_clear(size, ws->start); \
            ws->start = NULL; \
            ws->end = NULL; \

#if CC_USE_HEAP_FOR_WORKSPACE

#if CC_KERNEL

/* Use IOKit's memory allocation services. */

#include <IOKit/IOLib.h>

#define CC_WORKSPACE_DECL_N(ws, n) \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = IOMalloc(ccn_sizeof_n(n)); \
            ws->end = ws->start + ccn_sizeof_n(n); \

#define CC_WORKSPACE_FREE_N(ws, n) \
            IOFree(ws->start, ccn_sizeof_n(n)); \
            ws->end = NULL; \

#define CC_WORKSPACE_DECL(ws, size) \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = IOMalloc(size); \
            ws->end = ws.start + size; \

#define CC_WORKSPACE_FREE(ws, size) \
            IOFree(ws->start, size); \
            ws->end = NULL; \

#else

/* Linux, Windows, darwinOS, etc. */

#if __APPLE__
#include <sys/malloc.h>
#else
#include <malloc.h>
#endif

#define CC_WORKSPACE_DECL_N(ws, n) \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = malloc(ccn_sizeof_n(n)); \
            ws->end = ws->start + ccn_sizeof_n(n); \

#define CC_WORKSPACE_FREE_N(ws, n) \
            free(ws->start); \
            ws->start = NULL; \
            ws->end = NULL; \

#define CC_WORKSPACE_DECL(ws, size) \
            cc_ws ws##_ctx; \
            cc_ws_t ws = &ws##_ctx; \
            ws->start = malloc(size); \
            ws->end = ws->start + size; \

#define CC_WORKSPACE_FREE(ws, size) \
            free(ws->start); \
            ws->end = NULL; \

#endif

#else

#define CC_WORKSPACE_DECL_N(ws, n) CC_WORKSPACE_STACK_DECL_N(ws, n)

#define CC_WORKSPACE_FREE_N(ws, n) CC_WORKSPACE_STACK_FREE_N(ws, n)

#define CC_WORKSPACE_DECL(ws, size) CC_WORKSPACE_STACK_DECL(ws, n)

#define CC_WORKSPACE_FREE(ws, size) CC_WORKSPACE_STACK_FREE(ws, n)

#endif /* CC_USE_HEAP_FOR_WORKSPACE */

#endif /* _CORECRYPTO_CC_MEMORY_H_ */
