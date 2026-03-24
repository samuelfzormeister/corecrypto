includes("corecrypto_base.lua")

target("libRSPParser")
    set_kind("static")

    set_languages("c++17")

    add_sysincludedirs(
        "$(projectdir)/rsplib/include"
    )

    add_files(
        "$(projectdir)/rsplib/src/*.cpp"
    )

