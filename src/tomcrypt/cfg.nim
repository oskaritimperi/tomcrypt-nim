type
    ulong64* {.importc:"ulong64", header:"tomcrypt.h".} = uint64

    ulong32* {.importc:"ulong32", header:"tomcrypt.h".} = uint32

    ltc_mp_digit* {.importc:"ltc_mp_digit", header:"tomcrypt.h".} = uint64

const
    LTC_ENCRYPT = 0
    LTC_DECRYPT = 1
