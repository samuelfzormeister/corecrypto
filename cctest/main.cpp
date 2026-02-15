//
//  main.c
//  cctest
//
//  Created by Zormeister on 25/1/2025.
//

#include <iostream>
#include <string.h>
#include <string>

extern "C" {
#include <corecrypto/cctest_priv.h>
}

static bool trace = false;

static uint32_t flags = 0;

void set_flag(std::string &str)
{
    if (str == "md2") {
        flags |= CCTEST_ENABLE_MD2;
    }
    if (str == "md4") {
        flags |= CCTEST_ENABLE_MD4;
    }
    if (str == "aes") {
        flags |= CCTEST_ENABLE_AES;
    }
    if (str == "md5") {
        flags |= CCTEST_ENABLE_MD5;
    }
    if (str == "ripemd") {
        flags |= CCTEST_ENABLE_RIPEMD;
    }
}

void parse_test_list_string(std::string &enabled)
{
    char tmp[64];
    size_t len = enabled.length();
    const char *c_str = enabled.c_str();
    size_t off = enabled.find(",");
    size_t index = 0;
    
    if (off == std::string::npos) {
        enabled.copy(tmp, (len - index), index);
        std::string tmps = tmp;
        std::cout << tmps << std::endl;
        set_flag(tmps);
    }

    while (off != std::string::npos) {
        try {
            enabled.copy(tmp, (off) - index, index);
        } catch (std::runtime_error &err) {
            err.what();
        }
        std::string tmps = tmp;
        std::cout << tmps << std::endl;
        set_flag(tmps);
        index += off+1;
        off = enabled.find(",", index);
        memset(tmp, 0, sizeof(tmp));
    }
    
    if (off == std::string::npos) {
        enabled.copy(tmp, (len - index), index);
        std::string tmps = tmp;
        std::cout << tmps << std::endl;
        set_flag(tmps);
    }
}

//
// cctest -run aes-ecb,md4
//
void parse_args(int argc, const char *argv[]) {
    for (int i = 0; i < argc; i++) {
        std::string str = argv[i];
        if (str == "-trace") {
            trace = true;
        } else if (str == "-run") {
            std::string enabled = argv[i+1];
            if (enabled == "all") {
                flags = CCTEST_ENABLE_ALL;
            } else {
                parse_test_list_string(enabled);
            }
        }
    }
}

int main(int argc, const char *argv[])
{
    parse_args(argc, argv);
    cctest_enable_trace(trace);
    cctest_conduct_tests(flags);

    return 0;
}
