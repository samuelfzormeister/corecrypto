# Darwin 19 Requirements

The strikethroughs represent functionality that has been completed (and likely untested)

## Userspace Library Requirements

### CommonCrypto compatibility

CommonCrypto requires the following from corecrypto:
- AES block cipher operations in ~~CBC, ECB, CFB8, CTR, CFB, OFB, XTS,~~ GCM and CCM modes
- AES Key Wrapping
- An implementation of the ANSI Key Derivation function
- ~~An implementation of the HMAC Key Derivation function~~
- An implementation of the NIST Key Derivation function
- ~~An implementation of the PBKDF2 key derivation function~~
- ~~Blowfish operations~~
- ~~CAST block cipher operations~~
- ~~CMAC operation~~
- CKG (Collaborative Key Generation)
- ~~DES operations~~
- Diffie-Hellman operations
- Elliptic Curve cryptography functions
- ~~HMAC operation~~
- ~~MD2 digest algorithm~~
- ~~MD4 digest algorithm~~
- ~~MD5 digest algorithm~~
- ~~RC2 cipher~~
- ~~RC4 stream cipher~~
- RSA operations
- ~~RIPEMD-160 digest algorithm~~
- ~~SHA-1 digest algorithm~~
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~
- Padding functions

### Security framework compatibility

The Security project requires the following implementations from corecrypto:
- AES block cipher operations in GCM mode
- AES Key Wrapping
- An implementation of the ANSI Key Derivation function
- ~~An implementation of the HMAC Key Derivation function~~
- ~~An implementation of the PBKDF2 key derivation function~~
- DER encoding/decoding
- DER encoding/decoding of Elliptic Curve keys
- Diffie-Hellman operations
- Elliptic Curve cryptography functions
- Elliptic Curve Integreated Encryption Scheme cryptography functions
- Elliptic Curve cryptography using the 25519 curve.
- ~~HMAC operation~~
- ~~MD5 digest algorithm~~
- ~~PBKDF2 based PRNG~~
- RNG implementations
- RSA operations
- Secure Remote Password protcol related operations
- ~~SHA-1 digest algorithm~~
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~

### Heimdal framework compatibility

The Heimdal project requires the following implementations from corecrypto:
- ~~An implementation of the PBKDF2 key derivation function~~
- Diffie-Hellman operations
- Elliptic Curve cryptography functions
- Elliptic Curve cryptography using the 25519 curve.
- Secure Remote Password protcol related operations
- ~~SHA-1 digest algorithm~~
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~

### coreTLS compatibility

The coreTLS project requires the following implementations from corecrypto:
- AES block cipher operations in GCM mode
- ~~DES operations~~
- Diffie-Hellman operations
- Elliptic Curve cryptography functions
- ~~HMAC operation~~
- ~~MD5 digest algorithm~~
- RNG implementations
- RSA operations
- ~~SHA-1 digest algorithm~~
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~

### security_certificates compatibility

The security_certificates project requires the following implementations from corecrypto:
- ~~SHA-1 digest algorithm~~
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~

### OpenLDAP compatibility

The OpenLDAP project requires the following implementations from corecrypto:
- Secure Remote Password protcol related operations
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~

### passwordserver_sasl compatibilty

The passwordserver_sasl project requires the following implementations from corecrypto:
- Secure Remote Password protcol related operations
- ~~SHA-224 digest algorithm~~
- ~~SHA-256 digest algorithm~~
- ~~SHA-384 digest algorithm~~
- ~~SHA-512 digest algorithm~~
- RNG implementations

## Kernel-Mode compatibility

XNU has various interfaces to corecrypto, XNU wants the following cryptographic interfaces:
- ~~ChaCha20 cipher + a Poly1305 authentication tag~~
- ~~The CAST cipher in ECB mode~~
- ~~XTS and~~ CBC padding functions
- AES block ciper operations in ~~CBC, ECB, CTR, XTS~~ and GCM modes
- ~~RC4 stream cipher~~
- RSA operations
- ~~DES functions and in CBC and ECB mode.~~
- ~~Triple DES in CBC and ECB mode~~
- ~~Blowfish cipher in ECB mode~~

> [!WARNING]
> This was written using xnu-12377.1.9 as a reference.
> 
> It is likely to be non-reflective in some aspects, notably Blowfish and RC4.
>
Usage locations:
- AES GCM and CBC, DES, DES3 and ChaCha20-Poly1305 are utilised in `bsd/netinet6/esp_core.c` as a backing for ipsec cryptography (see `bsd/netkey/key.c`, `bsd/netinet6/esp_input.c` and `bsd/netinet6/esp_output.c`).
- HMAC is used in `bsd/netinet6/ah_core.c`, another component of ipsec alongside `bsd/netinet/flow_divert.c`
- SHA-1, SHA2-256, SHA2-384 and SHA2-512 are wrapped around using BSD KPI (see `libkern/crypto/corecrypto_sha2.c` and related files).
- RSA is used in the kernel to verify BaseSystem.dmg chunklist files (`bsd/kern/chunklist.c`), and is also likely used by other kernel extensions.
- ECC isn't used by the kernel directly, but is exported by the kext build of CoreCrypto.
- CTS3 padding is used in `bsd/nfs/gss/gss_krb5_mech.c` as a backing for the `CRYPTO_CTS_ENABLE` flag.
- The AES-CTR based DRBG is used by XNU to back the `cc_rand_generate` function, which is used by `osfmk/vm/vm_compressor_backing_store.c` and `bsd/netkey/key.c`

## Additional Notes

### Collaborative Key Generation

[This CMVP document](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4390.pdf) makes several refernces as to the nature of the CKG implementation.

Note-worthy tidbits from this document are in the Sensitive Security Parameter Managemnet section:
- 'Key Generation (ANSI X9.31) (CKG using method in Sections 4 and 5.1 [SP 800-133])'
- ECDSA Key Pair : 'The key pairs are generated conformant to SP800-133r2 (CKG) using FIPS186-4 Key Generation method, and the random value used in the key generation is generated using SP800-90A DRBG'
- RSA Key Pair : 'The key pairs are generated conformant to SP800-133r2 (CKG) using FIPS186-4 Key Generation method, and the random value used in the key generation is generated using SP800-90A DRBG'

Key / SSP generation:
-  'The module generates Keys and SSPs in accordance with FIPS 140-3 IG D.H. The cryptographic module performs Cryptographic Key Generation (CKG) for asymmetric keys as per [SP800-133r2] sections 4 and 5.1 (vendor affirmed), compliant with [FIPS186-4], and using DRBG compliant with [SP800-90A]. A seed (i.e., the random value) used in asymmetric key generation is a direct output from [SP800-90A] DRBG. The key generation service for RSA, ECDSA, as well as the [SP 800-90A] DRBG have been ACVT tested with algorithm certificates found in Table 4.'

