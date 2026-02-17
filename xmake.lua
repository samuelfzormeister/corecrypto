set_policy("check.auto_ignore_flags", false)

includes("llvm_toolchain.lua")

if is_plat("linux") then
   --  set_toolchains("llvm-linux")
elseif is_plat("windows") then
    set_toolchains("llvm-windows")
end

add_sysincludedirs(
    "$(projectdir)/src/cc/include",
    "$(projectdir)/src/ccaes/include",
    "$(projectdir)/src/ccansikdf/include",
    "$(projectdir)/src/ccblowfish/include",
    "$(projectdir)/src/cccast/include",
    "$(projectdir)/src/ccchacha20poly1305/include",
    "$(projectdir)/src/cccmac/include",
    "$(projectdir)/src/ccder/include",
    "$(projectdir)/src/ccdes/include",
    "$(projectdir)/src/ccdh/include",
    "$(projectdir)/src/ccdigest/include",
    "$(projectdir)/src/ccdrbg/include",
    "$(projectdir)/src/ccec/include",
    "$(projectdir)/src/ccec25519/include",
    "$(projectdir)/src/ccecies/include",
    "$(projectdir)/src/cchkdf/include",
    "$(projectdir)/src/cchmac/include",
    "$(projectdir)/src/cckeccak/include",
    "$(projectdir)/src/ccmd2/include",
    "$(projectdir)/src/ccmd4/include",
    "$(projectdir)/src/ccmd5/include",
    "$(projectdir)/src/ccmode/include",
    "$(projectdir)/src/ccn/include",
    "$(projectdir)/src/ccnistkdf/include",
    "$(projectdir)/src/ccpad/include",
    "$(projectdir)/src/ccpbkdf2/include",
    "$(projectdir)/src/ccprime/include",
    "$(projectdir)/src/ccrc2/include",
    "$(projectdir)/src/ccrc4/include",
    "$(projectdir)/src/ccripemd/include",
    "$(projectdir)/src/ccrng/include",
    "$(projectdir)/src/ccrsa/include",
    "$(projectdir)/src/ccsha1/include",
    "$(projectdir)/src/ccsha2/include",
    "$(projectdir)/src/ccsha3/include",
    "$(projectdir)/src/ccsrp/include",
    "$(projectdir)/src/ccwrap/include",
    "$(projectdir)/src/ccxof/include",
    "$(projectdir)/src/ccz/include",
    "$(projectdir)/src/cczp/include",
    "$(projectdir)/src/fips/include"
)

add_sysincludedirs("$(projectdir)/src/cctest/include")

target("libcorecrypto_static")
    set_kind("static")
    set_basename("corecrypto_static")

    add_files(
        "src/**.c"
    )

    if is_arch("x86_64", "i386") then
        add_files("src/ccaes/intel/*.c")
        add_files("src/ccaes/intel/*.s")

        remove_files(
            "src/ccaes/intel/Data.s",
            "src/ccaes/intel/EncryptDecrypt.s",
            "src/ccaes/intel/ExpandKeyForDecryption.s",
            "src/ccaes/intel/ExpandKeyForEncryption.s"
        )
    end

    remove_files(
        "src/cc_kext/*.c",
        "src/cckprng/**.c",
        "src/cckprng/yarrow/*.c",
        "src/*/test/*.c",
        "src/cctest/*.c"
    )

    add_cflags("-Wincompatible-pointer-types", "-Wno-int-conversion")
    add_asflags("-x assembler-with-cpp")

    if is_plat("linux") then
        add_cflags("-DCC_LINUX_ASM=1")
        add_asflags("-DCC_LINUX_ASM=1")
    end

target("libcorecrypto")
    set_kind("shared")
    set_basename("corecrypto")

    add_files(
        "src/**.c"
    )

    if is_arch("x86_64", "i386") then
        add_files("src/ccaes/intel/*.c")
        add_files("src/ccaes/intel/*.s")

        remove_files(
            "src/ccaes/intel/Data.s",
            "src/ccaes/intel/EncryptDecrypt.s",
            "src/ccaes/intel/ExpandKeyForDecryption.s",
            "src/ccaes/intel/ExpandKeyForEncryption.s"
        )
    end

    -- The yarrow PRNG won't compile for Linux, and I doubt it'll compile on Windows without modifications.
    -- Also I don't think we want Darwin Kernel Extension code compiled on a non-Darwin (or non-Userspace) platform.
    remove_files(
        "src/cc_kext/*.c",
        "src/cckprng/**.c",
        "src/cckprng/yarrow/*.c",
        "src/*/test/*.c"
    )


    add_cflags("-Wincompatible-pointer-types", "-Wno-int-conversion")
    add_asflags("-x assembler-with-cpp")
    add_ldflags("-fPIC")

    if is_plat("linux") then
        add_cflags("-DCC_LINUX_ASM=1")
        add_asflags("-DCC_LINUX_ASM=1")
    end

target("libcorecrypto_noasm")
    set_kind("shared")
    set_basename("corecrypto_noasm")

    add_files(
        "src/**.c"
    )

    -- Build a non-Assembly utilising copy of corecrypto for sanity's sake.
    -- Can't have a crypto library if it doesn't work without assembly.
    -- Or compiler intrinsics for that matter.
    add_defines("CC_USE_ASM=0")

    remove_files(
        "src/cc_kext/*.c",
        "src/cckprng/**.c",
        "src/cckprng/yarrow/*.c",
        "src/*/test/*.c"
    )

    add_cflags("-Wincompatible-pointer-types", "-Wno-int-conversion")

target("libcc_test")
    set_kind("static")
    set_basename("cc_test")

    add_sysincludedirs("$(projectdir)/src/cctest/include")
    
    add_defines("CORECRYPTO_TEST=1")

    -- Add infrastructure
    add_files(
        "src/cctest/cctest.c",
        "src/cctest/cctest_trace.c",
        "src/ccdigest/test/ccdigest_test.c",
        "src/ccmode/test/ccmode_test_ecb.c"
    )

    -- AES
    add_files(
        "src/ccaes/test/ccaes_ecb_test.c",
        "src/cctest/cctest_link_aes_ecb.c"
    )

    -- MD2
    add_files(
        "src/ccmd2/test/ccmd2_ti.c"
    )

    -- MD4
    add_files(
        "src/ccmd4/test/ccmd4_ti.c"
    )

    -- MD5
    add_files(
        "src/ccmd5/test/ccmd5_ti.c"
    )

    -- RIPEMD
    add_files(
        "src/ccripemd/test/ccrmd160_ti.c"
    )

    -- SHA-1
    add_files(
        "src/ccsha1/test/ccsha1_ti.c"
    )

    -- SHA-2
    add_files(
        "src/ccsha2/test/ccsha224_ti.c",
        "src/ccsha2/test/ccsha256_ti.c",
        "src/ccsha2/test/ccsha384_ti.c",
        "src/ccsha2/test/ccsha512_224_ti.c",
        "src/ccsha2/test/ccsha512_256_ti.c",
        "src/ccsha2/test/ccsha512_ti.c"
    )

target("cctest")
    set_kind("binary")

    -- Link with the static version of libcorecrypto.
    add_deps("libcc_test", "libcorecrypto_static")

    add_sysincludedirs("$(projectdir)/src/cctest/include")

    add_files("$(projectdir)/src/cc_tools/cctest.cpp")

target("librsp")
    set_kind("static")
    set_languages("c++17")

    add_sysincludedirs(
        "$(projectdir)/include",
        "$(projectdir)/src/cc_tools/include"
    )

    add_files(
        "$(projectdir)/src/cc_tools/lib/*.cpp"
    )

target("rsp2header")
    set_kind("binary")
    add_deps("librsp")

    set_languages("c++17")

    add_sysincludedirs(
        "$(projectdir)/include",
        "$(projectdir)/src/cc_tools/include"
    )

    add_files(
        "$(projectdir)/src/cc_tools/rsp2header.cpp"
    )
