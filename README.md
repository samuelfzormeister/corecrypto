# corecrypto

> [!NOTE]
> Despite the similar name, this library is **not** based on the released
> source bundle for Apple’s corecrypto implementation, because that code
> is not licensed for re-use. This library is based on the
> [botan](https://github.com/randombit/botan) and [LibTomCrypt](https://github.com/libtom/libtomcrypt/) libraries, as well as the
> [pdcrypto](https://github.com/rafirafi/pdcrypto) code.

> [!WARNING]
> This project contains experimental (and highly unstable) code!
> Do **NOT** use this project in a production environment!
>
> Additionally, this project relies on private headers from XNU for both `libcorecrypto` and `corecrypto_kernel` on Darwin based platforms.
>
> This project is also untested, so the chance for logic bugs is high. Currently, work is being done to implement a unit testing framework.
>

The `corecrypto` project is a low-level cryptography library designed for portability and ease of use, supplying digest functions and encryption modes, alongside other crypographic operations.

For a build of corecrypto **without** the utilities and binaries used during development, use the included `corecrypto_darwin` target.
- `xcodebuild clean build -target corecrypto_darwin`


The `corecrypto` project has several targets:
- `corecrypto_user`, the userspace library target.
- `corecrypto_static`, the static library form of corecrypto, used for the [dyld](https://github.com/apple-oss-distributions/dyld) project
- `corecrypto_kernel`, the kernel extension for Darwin, utilised by XNU and other components.
- `corecrypto_test`, the infrastructure and unit tests for testing the corecrypto project.
- `librsp`, a static library used internally for parsing the RSP files provided by the NIST.
- `cctest`, a userspace binary that integrates with `libcorecrypto_test` to conduct tests on the library.
- `prng_seedctl`, a binary ran by launchd that updates the kernel PRNG's seed.

> [!IMPORTANT]
> At the moment, this fork of the base corecrypto repository is architected to work with the Darwin 19 Kernel fork found [here](https://github.com/samuelfzormeister/xnu/tree/6153/ad_reset).
> Any other environments *will* work, however ceratin functions may be inaccessible, eg: the AVX-512 based SHA-512 check depends on the extension to `i386_cpuid_info_t`, the base SHA extension checker should work fine for the kernel, but is not available in userspace as the `kHasSHA` bit is not defined in `<System/i386/cpu_capabilities.h>`.

## SDK Integration

The corecrypto project headers are easy to integrate with new and pre-existing SDKs.

At most, the `corecrypto_user` library requires:
- The `Libc` project headers
- XNU's headers

To install the corecrypto project headers into the SDK, it's as easy as running:
`xcodebuild installhdrs -target corecrypto_user DSTROOT=$(xcrun -sdk macosx --show-sdk-path)`

## Installed binaries

- `/System/Library/Extensions/corecrypto.kext`
- `/usr/lib/system/libcorecrypto.dylib`
- `/usr/lib/system/libcorecrypto_noasm.dylib`
- `/usr/local/bin/cctest`
- `/usr/local/bin/rsp2header`
- `/usr/local/lib/librsp.a`
- `/usr/local/lib/system/libcorecrypto.a`
- `/usr/local/lib/libcorecrypto_test.a`
- `/usr/local/lib/libcorecrypto_test.dylib`

## Tested Implementations

The following components of the corecrypto have been validated and are known to be outputting good values:
- ccmd2
- ccmd4
- ccmd5
- ccrmd160
- ccsha1   (LTC)
- ccsha224 (LTC)
- ccsha256 (LTC)
- ccsha384 (LTC)
- ccsha512 (LTC)
- ccsha512_224 (LTC)
- ccsha512_256 (LTC)
- ccaes (ECB, LTC)
- ccaes (CBC, Gladman)
- ccaes (ECB, Intel Opt ASM)
- ccaes (ECB, Intel AES-NI ASM)
- ccaes (CBC, Intel Opt ASM)
- ccaes (CBC, Intel AES-NI ASM)

Bug reports are encouraged! File a report if an implementation is broken!
