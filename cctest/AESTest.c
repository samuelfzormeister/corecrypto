//
//  AESTest.c
//  cctest
//
//  Created by Zormeister on 4/5/2025.
//

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_impl.h>
#include <corecrypto/cc_priv.h>

enum CIPHER_MODE {
    ECB,
    CBC,
};

struct AES_VECTOR {
    enum CIPHER_MODE Mode;
    size_t key_size;
    const uint8_t iv[16];
    const uint8_t key[32]; /* maximum key size is 256 bits. */
    size_t ct_size;
    size_t pt_size;
    const uint8_t *pt;
    const uint8_t *ct;
};

const uint8_t kAESTestPlaintext1[] = { 0x6a, 0x84, 0x86, 0x7c, 0xd7, 0x7e, 0x12, 0xad, 0x07, 0xea, 0x1b, 0xe8, 0x95, 0xc5, 0x3f, 0xa3 };
const uint8_t kAESTestCiphertext1[] = { 0x73, 0x22, 0x81, 0xc0, 0xa0, 0xaa, 0xb8, 0xf7, 0xa5, 0x4a, 0x0c, 0x67, 0xa0, 0xc4, 0x5e, 0xcf };

struct AES_VECTOR AES_VECTORS[] = {
    {
        ECB,
        CCAES_KEY_SIZE_128,
        { 0 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        CCAES_BLOCK_SIZE,
        CCAES_BLOCK_SIZE,
        kAESTestPlaintext1,
        kAESTestCiphertext1,
    }
};

int TestAESECB()
{
    cc_try_abort("bowomp...");
    for (int i = 0; i < sizeof(AES_VECTORS) / sizeof(struct AES_VECTOR); i++) {
        const struct ccmode_ecb *ecb = ccaes_ecb_encrypt_mode();
    }
}
