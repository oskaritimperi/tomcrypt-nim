# Package

version       = "0.1.0"
author        = "Oskari Timperi"
description   = "libtomcrypt for Nim"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 0.18.0"
requires "tommath"

before install:
    if not existsEnv("TOMCRYPT_NO_CLONE"):
        exec "git clone --branch v1.18.1 --depth 1 https://github.com/libtom/libtomcrypt.git /tmp/source-libtomcrypt"

    exec "nim c -r tools/libtomcrypt.nim"
