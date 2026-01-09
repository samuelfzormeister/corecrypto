#  Foundational Knowledge

## Cipher Modes

'Cipher Mode' is a fancy way of saying how a cipher is utilised, for example: ECB (Electronic Code Book) mode is the underlying cipher itself, whilst other 'modes' revolve around using the cipher, but doing different operations with the result.

Common cipher modes include:
 - ECB (Electronic Code Book)
 - CBC (Cipher Block Chaining)
 - CFB (Cipher Feedback)
 - CTR (Counter)
 - OFB (Output Feedback)

Other known modes, which are usually used with AES, are:
- CCM (Counter with CMAC, used in 802.11i)
- GCM (Galois/Counter Mode, used in TLS, SSH, WPA-3 Enterprise and more)
- XTS (XEX-based Tweaked codebook mode with Ciphertext stealing, this should be recognisable as the mode for Full Disk Encryption)

## cc<xyz> Subsystems

| Subsystem              | Cryptographic function                                                               |
| ---------------------- | ------------------------------------------------------------------------------------ |
| ``ccaes``              | AES cipher                                                                           |
| ``ccasn1``             | ASN.1 data encoding                                                                  |
| ``ccansikdf``          | ANSI Key Derivation Function                                                         |
| ``ccblowfish``         | Blowfish cipher                                                                      |
| ``cccast``             | CAST cipher                                                                          |
| ``ccchacha20poly1305`` | ChaCha20 cipher + Poly1305 authentication                                            |
| ``cccmac``             | Cipher-Block-Chain MAC (NIST SP800-38B)                                              |
| ``ccder``              | Distinguised Encoding Rules encoding of ASN.1                                        |
| ``ccdes``              | DES (Data Encryption Standard) cipher                                                |
| ``ccdh``               | Diffie-Hellman key exchange                                                          |
| ``ccdigest``           | Generic API for cryptographic hashes                                                 |
| ``ccdrbg``             | Deterministic Random Bit Generator (SP800-90A rev 1)                                 |
| ``ccec``               | Elliptic Curve based cryptography                                                    |
| ``ccec25519``          | Elliptic Curve cryptography using curve 25519                                        |
| ``ccecies``            | Elliptic Curve Integrated Encryption Scheme                                          |
| ``cchkdf``             | HMAC based Key Derivation Function                                                   |
| ``cchmac``             | Hash based MAC                                                                       |
| ``cckeccak``           | Keccak algorithm, used in SHA-3 and XOFs                                             |
| ``cckprng``            | Kernel PRNG, currently Yarrow but I want to shift to Fortuna eventually              |
| ``ccmd2``              | MD2 hash algorithm                                                                   |
| ``ccmd4``              | MD4 hash algorithm                                                                   |
| ``ccmd5``              | MD5 hash algorithm                                                                   |
| ``ccmode``             | Cipher mode API infrastructure + base variants                                       |
| ``ccn``                | CoreCrypto Numerics, for large integers to be represented and stored                 |
| ``ccnistkdf``          | NIST Key Derivation Functions (SP800-108r1)                                          |
| ``ccpad``              | Ciphertext padding, PKCS#7, the various NIST CTS methods, etc.                       |
| ``ccpbkdf2``           | Password Based Key Derivation Function (2)                                           |
| ``ccrc2``              | RC2 encryption cipher                                                                |
| ``ccrc4``              | RC4 stream cipher                                                                    |
| ``ccripemd``           | RIPEMD hashing algorithm, only the 160 variant in Darwin 19.                         |
| ``ccrng``              | Random Number Generator, KPRNG in the kernel, a CTR DRBG in Darwin's userspace       |
| ``ccrsa``              | RSA algorithm functions                                                              |
| ``ccsha1``             | SHA-1 hashing algorithm                                                              |
| ``ccsha2``             | SHA-256 and SHA-512 + derivative hashing algorithm                                   |
| ``ccsha3``             | SHA-3 hashing algorithm                                                              |
| ``ccspake``            | SPAKE2, I believe                                                                    |
| ``ccsrp``              | Secure Remote Password key exchange                                                  |
| ``ccss_shamir``        | Shamir's Secret Sharing                                                              |
| ``ccvrf``              | Verifiable Random Functions (draft-irtf-cfrg-vrf-03)                                 |
| ``ccwrap``             | AES Key Wrapping operations                                                          |
| ``ccxof``              | eXtended Output Functions, defined in FIPS-202                                       |
| ``ccz``                | Generic Big Number handler, utilising cc_units                                       |
| ``cczp``               | Large prime number representation, ccz's beefier cousin.                             |

This list isn't reflective of the latest versions of `*OS`.
