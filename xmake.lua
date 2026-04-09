set_policy("check.auto_ignore_flags", false)

includes("xmake/toolchain.lua")

if is_plat("linux") then
    -- set_toolchains("llvm-linux")
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
    "$(projectdir)/src/ccscrypt/include",
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

includes("xmake/corecrypto_static.lua")
includes("xmake/corecrypto_test.lua")
includes("xmake/corecrypto_tools.lua")
includes("xmake/corecrypto_user.lua")
includes("xmake/corecrypto_noasm.lua")
includes("xmake/rsplib.lua")
