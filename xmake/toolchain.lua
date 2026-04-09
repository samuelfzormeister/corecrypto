-- so the GNU assembler doesn't like C++ style comments
-- which is annoying since there's a lot of them in CoreCrypto's ASM.

toolchain("llvm-linux")
    set_kind("standalone")

    -- set_toolset("cc", "clang")
    -- set_toolset("cxx", "clang", "clang++")
    -- set_toolset("ld", "ld.lld", "ld.lld")
    set_toolset("sh", "clang++", "clang")
    -- set_toolset("ar", "llvm-ar")
    -- set_toolset("ex", "llvm-ar")
    set_toolset("strip", "strip")
    set_toolset("mm", "clang")
    set_toolset("mxx", "clang", "clang++")
    -- set_toolset("as", "clang")

    on_check(function (toolchain)
        local ret = import("lib.detect.find_tool")("lld.ld")
        if ret then
            return import("lib.detect.find_tool")("clang")
        else
            return nil
        end
    end)

toolchain_end()

-- jesus...
toolchain("llvm-windows")
    set_kind("standalone")

    set_toolset("cc", "clang-cl")
    set_toolset("cxx", "clang-cl")

    -- Normal link.exe will bail trying to find msvcrt.lib, so use lld-link instead.
    set_toolset("ld", "lld-link")
    set_toolset("sh", "lld-link")

    set_toolset("ar", "llvm-ar")

    on_check(function (toolchain)
        local ret = import("lib.detect.find_tool")("lld-link")
        if ret then
            return import("lib.detect.find_tool")("clang")
        else
            return nil
        end
    end)

toolchain_end()
