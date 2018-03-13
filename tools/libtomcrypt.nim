import os
import strutils

import builder

# Import for tommathIncDir
import tommath / private / config

let sourceDir = expandFilename("/tmp/source-libtomcrypt")

let libtomcrypt = newStaticLibrary("tomcrypt", sourceDir)

add(libtomcrypt.defines, "USE_LTM")
add(libtomcrypt.defines, "LTM_DESC")
add(libtomcrypt.defines, "LTC_SOURCE")

when not defined(vcc):
    add(libtomcrypt.compilerOptions, "-O3 -funroll-loops -fomit-frame-pointer")

for file in walkDirRec(sourceDir / "src", {pcFile}, {pcDir}):
    if endsWith(file, ".c"):
        addSourceFiles(libtomcrypt, file)

addIncludeDirectory(libtomcrypt, sourceDir / "src" / "headers")
addIncludeDirectory(libtomcrypt, tommathIncDir)

for file in walkFiles(sourceDir / "src" / "headers" / "*.h"):
    addPublicHeaders(libtomcrypt, "include", expandFilename(file))

if build(libtomcrypt):
    install(libtomcrypt, getAppDir() / ".." / "src" / "tomcrypt" / "private")
