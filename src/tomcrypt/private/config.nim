import os

template currentSourceDir(): string =
    ## Return the directory the current source file resides in.
    parentDir(currentSourcePath())

when not defined(tomcryptPrefix):
    const tomcryptPrefix = currentSourceDir()

when not defined(tomcryptIncPath):
    const tomcryptIncPath = tomcryptPrefix / "include"

when defined(vcc):
    {.passC:"/I" & tomcryptIncPath.}
else:
    {.passC:"-I" & tomcryptIncPath.}

when not defined(tomcryptLibPath):
    const tomcryptLibPath = tomcryptPrefix / "lib"

when defined(vcc):
    const libraryPath = tomcryptLibPath / "tomcrypt.lib"
else:
    const libraryPath = tomcryptLibPath / "libtomcrypt.a"

{.passL:libraryPath.}
