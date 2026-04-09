/*
 *  cc_runtime_config.h
 *  corecrypto
 *
 *  Created on 09/18/2012
 *
 *  Copyright (c) 2012,2014,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef CORECRYPTO_CC_RUNTIME_CONFIG_H_
#define CORECRYPTO_CC_RUNTIME_CONFIG_H_

#include <corecrypto/cc_config.h>

/* Only intel systems have these runtime switches today. */

// --- Default version macros if <Kernel/libkern/version.h> is unavailable --- //
#define __CC_MAJOR_VERSION 19
#define __CC_MINOR_VERSION 6

#if defined(__x86_64__) || defined(__i386__)

#if CC_KERNEL
    #include <i386/cpuid.h>
    #define CC_HAS_RDRAND() ((cpuid_features() & CPUID_FEATURE_RDRAND) != 0)
    #define CC_HAS_AESNI() ((cpuid_features() & CPUID_FEATURE_AES) != 0)
    #define CC_HAS_SupplementalSSE3() ((cpuid_features() & CPUID_FEATURE_SSSE3) != 0)
    #define CC_HAS_AVX1() ((cpuid_features() & CPUID_FEATURE_AVX1_0) != 0)
    #define CC_HAS_AVX2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX2) != 0)
    #define CC_HAS_AVX512_AND_IN_KERNEL()    ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX512F) !=0)
    #define CC_HAS_SHA()  ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_SHA) != 0)

#elif CC_XNU_KERNEL_AVAILABLE
    #if !__has_include(<System/i386/cpu_capabilities.h>)
        #include <stdint.h>

        #define kHasSupplementalSSE3    0x00000100
        #define kHasAES                 0x00001000
        #define kHasAVX1_0              0x01000000
        #define kHasRDRAND              0x02000000
        // --- FMA might be of interest for ECC speedup. --- //
        #define kHasFMA                 0x10000000
        #define kHasAVX2_0              0x20000000
        #define kHasBMI2                0x80000000
        // --- ADX might be of interest for ccn. --- //
        #define kHasADX                 0x0000000400000000ULL

        // --- _cpu_capabilities has been uint64_t since 2050.48.11 --- //
        #if __has_include(<Kenrel/libkern/version.h>)
            #include <Kenrel/libkern/version.h>
        #else
            #define VERSION_MAJOR __CC_MAJOR_VERSION
            #define VERSION_MINOR __CC_MINOR_VERSION
        #endif

        #if VERSION_MAJOR > 12 || (VERSION_MAJOR == 12 && VERSION_MINOR >= 5)
            extern uint64_t _get_cpu_capabilities(void);
        #else
            // --- Should I just cut this section out? Who's using libcorecrypto on Lion or Snow Leopard? --- //
            extern int _get_cpu_capabilities(void);
        #endif
    #else
        #include <System/i386/cpu_capabilities.h>
    #endif

    #define CC_HAS_RDRAND() (_get_cpu_capabilities() & kHasRDRAND)

    #define CC_HAS_AESNI() (_get_cpu_capabilities() & kHasAES)
    #define CC_HAS_SupplementalSSE3() (_get_cpu_capabilities() & kHasSupplementalSSE3)
    #define CC_HAS_AVX1() (_get_cpu_capabilities() & kHasAVX1_0)
    #define CC_HAS_AVX2() (_get_cpu_capabilities() & kHasAVX2_0)

    // --- I wonder why Apple specifically needs and AND_IN_KERNEL check. --- //
    // --- Did they not port their AVX-512 code to userspace? --- //
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0

    // --- New bits introduced in custom kernels. --- //
#if CC_SYSTEM_HAS_SHA_BIT
    #define CC_HAS_SHA() (_get_cpu_capabilities() & kHasSHA)
#else
    #define CC_HAS_SHA() 0
#endif /* CC_SYSTEM_HAS_SHA_BIT */

#if CC_SYSTEM_HAS_SHA512_BIT
    #define CC_HAS_SHA512() (_get_cpu_capabilities() & kHasSHA512)
#else
    #define CC_HAS_SHA512() 0
#endif /* CC_SYSTEM_HAS_SHA512_BIT */

#elif __has_include(<cpuid.h>)
    #include <cpuid.h>
    #include <stdbool.h>
    #include <stdint.h>

    // --- libgcc doesn't cover every extension, I need to invoke CPUID. --- //

    #define __REGISTER_EAX 0
    #define __REGISTER_EBX 1
    #define __REGISTER_ECX 2
    #define __REGISTER_EDX 3

    CC_INLINE bool cpu_check_leaf1(uint32_t reg, uint32_t bit)
    {
        uint32_t cpuid[4] = {0,0, 0, 0};
        __cpuid(1, cpuid[__REGISTER_EAX], cpuid[__REGISTER_EBX], cpuid[__REGISTER_ECX], cpuid[__REGISTER_EDX]);
        return (cpuid[reg] & bit) != 0;
    }

    CC_INLINE bool cpu_check_leaf7(uint32_t sl, uint32_t reg, uint32_t bit)
    {
        uint32_t cpuid[4] = {7,0, sl, 0};
        __cpuid(7, cpuid[__REGISTER_EAX], cpuid[__REGISTER_EBX], cpuid[__REGISTER_ECX], cpuid[__REGISTER_EDX]);
        return (cpuid[reg] & bit) != 0;
    }

    // --- For further down the track, should RDSEED be used instead? --- //
    #define CC_HAS_RDRAND() cpu_check_leaf1(__REGISTER_ECX, bit_RDRND)
    #define CC_HAS_AESNI() cpu_check_leaf1(__REGISTER_ECX, bit_AESNI)
    #define CC_HAS_SupplementalSSE3() cpu_check_leaf1(__REGISTER_ECX, bit_SSSE3)
    #define CC_HAS_AVX1() cpu_check_leaf1(__REGISTER_ECX, bit_AVX)
    #define CC_HAS_AVX2() cpu_check_leaf7(0, __REGISTER_EBX, bit_AVX2)
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_SHA() cpu_check_leaf7(0, __REGISTER_EBX, bit_SHA)
    #define CC_HAS_SHA512() cpu_check_leaf7(1, __REGISTER_EAX, bit_SHA512)

#elif __has_include(<immintrin.h>)
    // --- Fallback if there's no cpuid.h available --- //

    #include <immintrin.h>
    #define CC_HAS_AESNI() _may_i_use_cpu_feature(_FEATURE_AES)
    #define CC_HAS_SupplementalSSE3() _may_i_use_cpu_feature(_FEATURE_SSSE3)
    #define CC_HAS_AVX1() _may_i_use_cpu_feature(_FEATURE_AVX)
    #define CC_HAS_AVX2() _may_i_use_cpu_feature(_FEATURE_AVX2)
    #define CC_HAS_AVX512_AND_IN_KERNEL()  0
    #define CC_HAS_SHA() _may_i_use_cpu_feature(_FEATURE_SHA)
    #define CC_HAS_SHA512() _may_i_use_cpu_feature_ext(_FEATURE_SHA512, 1)
#else
    #define CC_HAS_RDRAND() 0
    #define CC_HAS_AESNI() 0
    #define CC_HAS_SupplementalSSE3() 0
    #define CC_HAS_AVX1() 0
    #define CC_HAS_AVX2() 0
    #define CC_HAS_AVX512_AND_IN_KERNEL()  0
    #define CC_HAS_SHA() 0
#endif

#elif defined (__arm__) || defined (__arm64__)

#if CC_XNU_KERNEL_AVAILABLE || CC_KERNEL
    #if !__has_include(<System/arm/cpu_capabilities.h>)
        #include <stdint.h>

        #define kHasARMv8Crypto  0x01000000
        // --- We can still check for this bit --- //
        #define kHasARMv82SHA512 0x80000000

        // --- This is the easiest way to account for the change. --- //
        #if __has_include(<Kenrel/libkern/version.h>)
            #include <Kenrel/libkern/version.h>
        #else
            #define VERSION_MAJOR __CC_MAJOR_VERSION
            #define VERSION_MINOR __CC_MINOR_VERSION
        #endif
        #if VERSION_MAJOR >= 20
            extern uint64_t _get_cpu_capabilities(void);
        #else
            extern int _get_cpu_capabilities(void);
        #endif
    #else
        #include <System/arm/cpu_capabilities.h>
    #endif

    #define CC_HAS_NEON() (_get_cpu_capabilites() & kHasNeon)
    #define CC_HAS_SHA1() (_get_cpu_capabilites() & kHasARMv8Crypto)
    #define CC_HAS_SHA256() (_get_cpu_capabilites() & kHasARMv8Crypto)
    #define CC_HAS_SHA512() (_get_cpu_capabilites() & kHasARMv82SHA512)
    #define CC_HAS_SHA3() (_get_cpu_capabilites() & kHasARMv82SHA3)
    #define CC_HAS_AES() (_get_cpu_capabilites() & kHasARMv8Crypto)
#endif

#endif  // defined(__x86_64__) || defined(__i386__)

#endif /* CORECRYPTO_CC_RUNTIME_CONFIG_H_ */
