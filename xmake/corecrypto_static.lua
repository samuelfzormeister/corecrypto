includes("corecrypto_base.lua")

target("libcorecrypto_static")
    set_kind("static")
    set_basename("corecrypto")

    -- This should only include the files in the top directory.
    add_files(
        "$(projectdir)/src/cc/*.c",
        "$(projectdir)/src/ccaes/ltc/*.c",
        "$(projectdir)/src/ccaes/gladman/*.c",
        "$(projectdir)/src/ccaes/*.c",
        "$(projectdir)/src/ccansikdf/*.c",
        "$(projectdir)/src/ccblowfish/*.c",
        "$(projectdir)/src/cccast/*.c",
        "$(projectdir)/src/ccchacha20poly1305/*.c",
        "$(projectdir)/src/cccmac/*.c",
        "$(projectdir)/src/ccder/*.c",
        "$(projectdir)/src/ccdes/*.c",
        "$(projectdir)/src/ccdh/*.c",
        "$(projectdir)/src/ccdigest/*.c",
        "$(projectdir)/src/ccdrbg/*.c",
        -- "$(projectdir)/src/ccec/*.c",
        -- "$(projectdir)/src/ccec25519/*.c",
        -- "$(projectdir)/src/ccecies/*.c",
        "$(projectdir)/src/cchkdf/*.c",
        "$(projectdir)/src/cchmac/*.c",
        -- "$(projectdir)/src/cckeccak/*.c",
        "$(projectdir)/src/ccmd2/*.c",
        "$(projectdir)/src/ccmd4/*.c",
        "$(projectdir)/src/ccmd5/*.c",
        "$(projectdir)/src/ccmode/cbc/*.c",
        "$(projectdir)/src/ccmode/cfb/*.c",
        "$(projectdir)/src/ccmode/cfb8/*.c",
        "$(projectdir)/src/ccmode/ctr/*.c",
        "$(projectdir)/src/ccmode/gcm/*.c",
        "$(projectdir)/src/ccmode/ofb/*.c",
        "$(projectdir)/src/ccmode/xts/*.c",
        "$(projectdir)/src/ccn/*.c",
        -- "$(projectdir)/src/ccnistkdf/*.c",
        "$(projectdir)/src/ccpad/*.c",
        "$(projectdir)/src/ccpbkdf2/*.c",
        -- "$(projectdir)/src/ccprime/*.c",
        "$(projectdir)/src/ccrc2/*.c",
        "$(projectdir)/src/ccrc4/*.c",
        "$(projectdir)/src/ccripemd/*.c",
        "$(projectdir)/src/ccrng/*.c",
        "$(projectdir)/src/ccrng/pbkdf2/*.c",
        "$(projectdir)/src/ccrsa/*.c",
        "$(projectdir)/src/ccscrypt/*.c",
        "$(projectdir)/src/ccsha1/*.c",
        "$(projectdir)/src/ccsha2/*.c",
        -- "$(projectdir)/src/ccsha3/*.c",
        -- "$(projectdir)/src/ccsrp/*.c",
        "$(projectdir)/src/ccwrap/*.c",
        -- "$(projectdir)/src/ccxof/*.c",
        "$(projectdir)/src/ccz/*.c",
        "$(projectdir)/src/cczp/*.c"
    )

    -- If we're on x86 or IA32, enable the accelerated assembly.
    if is_arch("x86_64", "i386") then
        add_files("$(projectdir)/src/ccaes/intel/*.c")

        add_files(
            "$(projectdir)/src/ccaes/intel/aes_crypt_hw.s",
            "$(projectdir)/src/ccaes/intel/aes_key_hw.s",
            "$(projectdir)/src/ccaes/intel/aes_modes_asm.s",
            "$(projectdir)/src/ccaes/intel/aes_modes_hw.s",
            "$(projectdir)/src/ccaes/intel/AES.s",
            "$(projectdir)/src/ccaes/intel/aesxts_asm.s"
        )
    end


    add_cflags("-Wincompatible-pointer-types", "-Wno-int-conversion")
    add_asflags("-x assembler-with-cpp")
    add_ldflags("-fPIC")

    if is_plat("linux") then
        add_cflags("-DCC_LINUX_ASM=1")
        add_asflags("-DCC_LINUX_ASM=1")
    end
