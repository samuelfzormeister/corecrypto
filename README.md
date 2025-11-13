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
> The `VNG` (which allegedly stands for Apple's Vector & Numerics Group CoreOS team) implementations of AES are currently untested.
>
> This project is also untested, so the chance for logic bugs is high. Currently, work is being done to implement a unit testing framework.
>

The `corecrypto` project is a low-level cryptography library designed for portability and ease of use, supplying digest functions and encryption modes, alongside other crypographic operations.

The `corecrypto` project has several targets:
- `libcorecrypto`, the userspace library target.
- `libcorecrypto_noasm`, the userspace library target without any assembly.
- `corecrypto_kernel`, the kernel extension for Darwin, utilised by XNU and other components.
- `libcc_test`, all of the source code under the [test](src/test) directory for runtime testing if `libcorecrypto` was configured without testing infrastructure.

> [!IMPORTANT]
> At the moment, this fork of the base corecrypto repository is architected to work with the Darwin 19 Kernel fork found [here](https://github.com/samuelfzormeister/xnu/tree/6153/x86-dev).
> Any other environments *will* work, however ceratin functions may be inaccessible, eg: the AVX-512 based SHA-512 check depends on the extension to `i386_cpuid_info_t`, the base SHA extension checker should work fine for the kernel, but is not available in userspace as the `kHasSHA` bit is not defined in `<System/i386/cpu_capabilities.h>`.
