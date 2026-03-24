includes("corecrypto_base.lua")
includes("corecrypto_user.lua")

target("libcorecrypto_test_static")
    set_kind("static")
    set_basename("corecrypto_test")

    add_deps("libcorecrypto_static")

    add_sysincludedirs("$(projectdir)/src/cctest/include")
    
    add_defines("CORECRYPTO_TEST=1")

    -- Add infrastructure
    add_files(
        "$(projectdir)/src/cctest/cctest.c",
        "$(projectdir)/src/cctest/cctest_trace.c",
        "$(projectdir)/src/ccdigest/test/ccdigest_test.c",
        "$(projectdir)/src/ccmode/test/*.c"
    )

    -- AES
    add_files(
        "$(projectdir)/src/ccaes/test/*.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cbc.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cfb.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cfb8.c",
        "$(projectdir)/src/cctest/cctest_link_aes_ecb.c",
        "$(projectdir)/src/cctest/cctest_link_aes_ofb.c"
    )

    -- MD2
    add_files(
        "$(projectdir)/src/ccmd2/test/ccmd2_ti.c"
    )

    -- MD4
    add_files(
        "$(projectdir)/src/ccmd4/test/ccmd4_ti.c"
    )

    -- MD5
    add_files(
        "$(projectdir)/src/ccmd5/test/ccmd5_ti.c"
    )

    -- RIPEMD
    add_files(
        "$(projectdir)/src/ccripemd/test/ccrmd160_ti.c"
    )

    -- SHA-1
    add_files(
        "$(projectdir)/src/ccsha1/test/ccsha1_ti.c"
    )

    -- SHA-2
    add_files(
        "$(projectdir)/src/ccsha2/test/*_ti.c"
    )

    -- PBKDF2
    add_files(
        "$(projectdir)/src/ccpbkdf2/test/*.c"
    )

target("libcorecrypto_test")
    set_kind("shared")
    set_basename("corecrypto_test")

    -- We'll link to the dynamic version where possible.
    add_deps("libcorecrypto")

    add_sysincludedirs("$(projectdir)/src/cctest/include")
    
    add_defines("CORECRYPTO_TEST=1")

    -- Add infrastructure
    add_files(
        "$(projectdir)/src/cctest/cctest.c",
        "$(projectdir)/src/cctest/cctest_trace.c",
        "$(projectdir)/src/ccdigest/test/ccdigest_test.c",
        "$(projectdir)/src/ccmode/test/*.c"
    )

    -- AES
    add_files(
        "$(projectdir)/src/ccaes/test/*.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cbc.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cfb.c",
        "$(projectdir)/src/cctest/cctest_link_aes_cfb8.c",
        "$(projectdir)/src/cctest/cctest_link_aes_ecb.c",
        "$(projectdir)/src/cctest/cctest_link_aes_ofb.c"
    )

    -- MD2
    add_files(
        "$(projectdir)/src/ccmd2/test/ccmd2_ti.c"
    )

    -- MD4
    add_files(
        "$(projectdir)/src/ccmd4/test/ccmd4_ti.c"
    )

    -- MD5
    add_files(
        "$(projectdir)/src/ccmd5/test/ccmd5_ti.c"
    )

    -- RIPEMD
    add_files(
        "$(projectdir)/src/ccripemd/test/ccrmd160_ti.c"
    )

    -- SHA-1
    add_files(
        "$(projectdir)/src/ccsha1/test/ccsha1_ti.c"
    )

    -- SHA-2
    add_files(
        "$(projectdir)/src/ccsha2/test/*_ti.c"
    )

    -- PBKDF2
    add_files(
        "$(projectdir)/src/ccpbkdf2/test/*.c"
    )

target("corecrypto_test")
    set_kind("binary")
    set_languages("c++17")

    add_deps("libcorecrypto", "libcorecrypto_test_static")

    add_sysincludedirs("$(projectdir)/src/cctest/include")

    add_files("$(projectdir)/src/cc_tools/cctest.cpp")
