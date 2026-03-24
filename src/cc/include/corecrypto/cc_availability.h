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

#ifndef _CORECRYPTO_CC_AVAILABILITY_H_
#define _CORECRYPTO_CC_AVAILABILITY_H_

/*
 * TODO: figure out if these conflict with CommonCrypto.
 */

#if __has_feature(attribute_availability_with_replacement)

#if __has_feature(attribute_availability_bridgeos)
  #ifndef __CC_BRIDGE_OS_DEPRECATED
    #define __CC_BRIDGEOS_DEPRECATED_WITH_REPLACEMENT(_dep, _msg) __attribute__((availability(bridgeos,deprecated=_dep, replacement=_msg)))
    #define __CC_BRIDGEOS_DEPRECATED(_dep) __attribute__((availability(bridgeos,deprecated=_dep)))
  #endif
  #ifndef __CC_BRIDGE_OS_AVAILABLE
    #define __CC_BRIDGEOS_AVAILABLE(_dep) __attribute__((availability(bridgeos,introduced=_dep)))
  #endif
#endif

#ifndef __CC_BRIDGEOS_DEPRECATED
  #define __CC_BRIDGEOS_DEPRECATED_WITH_REPLACEMENT(_dep, _msg)
  #define __CC_BRIDGEOS_DEPRECATED(_dep)
#endif

#ifndef __CC_BRIDGEOS_AVAILABLE
  #define __CC_BRIDGEOS_AVAILABLE(_dep)
#endif

#define cc_deprecate_with_replacement(replacement_message, ios_version, macos_version, tvos_version, watchos_version, bridgeos_version) \
    __attribute__((availability(macos,deprecated=macos_version,       replacement=replacement_message)))\
    __attribute__((availability(ios,deprecated=ios_version,           replacement=replacement_message)))\
    __attribute__((availability(watchos,deprecated=watchos_version,   replacement=replacement_message)))\
    __attribute__((availability(tvos,deprecated=tvos_version,         replacement=replacement_message)))\
    __CC_BRIDGEOS_DEPRECATED_WITH_REPLACEMENT(bridgeos_version, replacement_message)

#define cc_deprecate(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version) \
    __attribute__((availability(macos,deprecated=macos_version)))       \
    __attribute__((availability(ios,deprecated=ios_version)))           \
    __attribute__((availability(watchos,deprecated=watchos_version)))   \
    __attribute__((availability(tvos,deprecated=tvos_version)))         \
    __CC_BRIDGEOS_DEPRECATED(bridgeos_version)

#define cc_available(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version) \
__attribute__((availability(macos,introduced=macos_version)))\
__attribute__((availability(ios,introduced=ios_version           )))\
__attribute__((availability(watchos,introduced=watchos_version   )))\
__attribute__((availability(tvos,introduced=tvos_version         )))\
__CC_BRIDGEOS_AVAILABLE(bridgeos_version)

#define cc_available_1(ios_version, macos_version) \
__attribute__((availability(macos,introduced=macos_version)))\
__attribute__((availability(ios,introduced=ios_version           )))\

#define cc_obsoleted(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version) \
__attribute__((availability(macos,obsoleted=macos_version)))\
__attribute__((availability(ios,obsoleted=ios_version           )))\
__attribute__((availability(watchos,obsoleted=watchos_version   )))\
__attribute__((availability(tvos,obsoleted=tvos_version         )))\
__CC_BRIDGEOS_AVAILABLE(bridgeos_version)

#define cc_ios_available(vers) __attribute__((availability(ios,introduced=vers)))
#define cc_macos_available(vers) __attribute__((availability(macos,introduced=vers)))
#define cc_watchos_available(vers) __attribute__((availability(watchos,introduced=vers)))
#define cc_tvos_available(vers) __attribute__((availability(tvos,introduced=vers)))
#define cc_bridgeos_available(vers) __CC_BRIDGEOS_AVAILABLE(vers)

#define cc_ios_deprecate(vers) __attribute__((availability(ios,deprecated=vers)))
#define cc_macos_deprecate(vers) __attribute__((availability(macos,deprecated=vers)))
#define cc_watchos_deprecate(vers) __attribute__((availability(watchos,deprecated=vers)))
#define cc_tvos_deprecate(vers) __attribute__((availability(tvos,deprecated=vers)))
#define cc_bridgeos_deprecate(vers) __CC_BRIDGEOS_DEPRECATED(vers)

#define cc_ios_deprecate_with_replacement(replacement_message, vers)                         \
    __attribute__((availability(ios,deprecated=vers,replacement=replacement_message)))
#define cc_macos_deprecate_with_replacement(replacement_message, vers)                       \
    __attribute__((availability(macos,deprecated=vers,replacement=replacement_message)))
#define cc_watchos_deprecate_with_replacement(replacement_message, vers)                     \
    __attribute__((availability(watchos,deprecated=vers,replacement=replacement_message)))
#define cc_tvos_deprecate_with_replacement(replacement_message, vers)                        \
    __attribute__((availability(tvos,deprecated=vers,replacement=replacement_message)))
#define cc_bridgeos_deprecate_with_replacement(replacement_message, vers)                    \
    __CC_BRIDGEOS_DEPRECATED_WITH_REPLACEMENT(vers, replacement_message)

#else /* !__has_feature(attribute_availability_with_replacement) */

#define cc_deprecate_with_replacement(replacement_message, ios_version, macos_version, tvos_version, watchos_version, bridgeos_version)
#define cc_deprecate(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version)
#define cc_available(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version)
#define cc_obsoleted(ios_version, macos_version, tvos_version, watchos_version, bridgeos_version)

#endif /* __has_feature(attribute_availability_with_replacement) */

/* all base corecrypto public APIs were available in 2012. */
#define CC_API_AVAILABLE_2012   \
    cc_macos_available(10.8)    \
    cc_ios_available(6.0)

#define CC_API_AVAILABLE_2013   \
    cc_macos_available(10.9)    \
    cc_ios_available(7.0)

#define CC_API_AVAILABLE_2014   \
    cc_macos_available(10.10)   \
    cc_ios_available(8.0)       \
    cc_watchos_available(1.0)

#define CC_API_AVAILABLE_FALL_2015  \
    cc_macos_available(10.11)       \
    cc_ios_available(9.0)           \
    cc_watchos_available(2.0)       \
    cc_tvos_available(9.0)

#define CC_API_AVAILABLE_FALL_2016  \
    cc_macos_available(10.12)       \
    cc_ios_available(10.0)          \
    cc_watchos_available(3.0)       \
    cc_tvos_available(10.0)

#define CC_API_AVAILABLE_FALL_2017  \
    cc_macos_available(10.13)       \
    cc_ios_available(11.0)          \
    cc_watchos_available(4.0)       \
    cc_tvos_available(11.0)         \
    cc_bridgeos_available(2.0)

#define CC_API_AVAILABLE_FALL_2018  \
    cc_macos_available(10.14)       \
    cc_ios_available(12.0)          \
    cc_watchos_available(5.0)       \
    cc_tvos_available(12.0)         \
    cc_bridgeos_available(3.0)

#define CC_API_AVAILABLE_FALL_2019  \
    cc_macos_available(10.15)       \
    cc_ios_available(13.0)          \
    cc_watchos_available(6.0)       \
    cc_tvos_available(13.0)         \
    cc_bridgeos_available(4.0)


#define CC_API_DEPRECATED_FALL_2019  \
    cc_macos_deprecate(10.15)        \
    cc_ios_deprecate(13.0)           \
    cc_watchos_deprecate(6.0)        \
    cc_tvos_deprecate(13.0)          \
    cc_bridgeos_deprecate(4.0)

// --- Long macro name, fix this? --- //
#define CC_API_DEPRECATED_WITH_REPLACEMENT_FALL_2019(msg)   \
    cc_macos_deprecate_with_replacement(msg, 10.15)         \
    cc_ios_deprecate_with_replacement(msg, 13.0)            \
    cc_watchos_deprecate_with_replacement(msg, 6.0)         \
    cc_tvos_deprecate_with_replacement(msg, 13.0)           \
    cc_bridgeos_deprecate_with_replacement(msg, 4.0)

#endif /* _CORECRYPTO_CC_AVAILABILITY_H_ */
