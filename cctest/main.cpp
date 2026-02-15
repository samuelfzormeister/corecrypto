//
//  main.c
//  cctest
//
//  Created by Zormeister on 25/1/2025.
//

#include <string>

extern "C" {
#include <corecrypto/cctest_priv.h>
}

#define CCTEST_MD2    0
#define CCTEST_MD4    0
#define CCTEST_RMD160 0

// fr gotta make more test cases
#if CCTEST_MD2
extern int TestMD2(void);
#endif
#if CCTEST_MD4
extern int TestMD4(void);
#endif
#if CCTEST_RMD160
extern int TestRMD160(void);
#endif

extern void TestChaCha20(void);

static bool trace = false;

void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "-trace") {
            trace = true;
        }
    }
}

int main(int argc, const char *argv[])
{
    cctest_enable_trace(trace);
    cctest_conduct_tests(CCTEST_ENABLE_ALL);

    return 0;
}
