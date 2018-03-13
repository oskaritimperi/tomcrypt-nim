import os

template currentSourceDir(): string =
    ## Return the directory the current source file resides in.
    parentDir(currentSourcePath())

when not defined(tomcryptPrefix):
    const tomcryptPrefix* = currentSourceDir()

when not defined(tomcryptIncDir):
    const tomcryptIncDir* = tomcryptPrefix / "include"

when defined(vcc):
    {.passC:"/I" & tomcryptIncDir.}
else:
    {.passC:"-I" & tomcryptIncDir.}

when not defined(tomcryptLibDir):
    const tomcryptLibDir* = tomcryptPrefix / "lib"

when defined(vcc):
    const tomcryptLibPath* = tomcryptLibDir / "tomcrypt.lib"
else:
    const tomcryptLibPath* = tomcryptLibDir / "libtomcrypt.a"

{.passL:tomcryptLibPath.}
