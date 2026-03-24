includes("corecrypto_base.lua")

target("librsp")
    set_kind("static")

    set_languages("c++17")

    add_sysincludedirs(
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
        "$(projectdir)/src/cc_tools/include"
    )

    add_files(
        "$(projectdir)/src/cc_tools/rsp2header.cpp"
    )
