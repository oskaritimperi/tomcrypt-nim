##  LibTomCrypt, modular cryptographic library -- Tom St Denis
##
##  LibTomCrypt is a library that provides various cryptographic
##  algorithms in a highly modular and flexible manner.
##
##  The library is free for all purposes without any express
##  guarantee it works.
##
##  ---- LTC_BASE64 Routines ----

proc base64_encode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                   outlen: ptr culong): cint {.importc: "base64_encode".}
proc base64_decode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                   outlen: ptr culong): cint {.importc: "base64_decode".}
proc base64_strict_decode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                          outlen: ptr culong): cint {.
    importc: "base64_strict_decode".}

proc base64url_encode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                      outlen: ptr culong): cint {.importc: "base64url_encode".}
proc base64url_strict_encode*(`in`: ptr cuchar; inlen: culong; `out`: ptr cuchar;
                             outlen: ptr culong): cint {.
    importc: "base64url_strict_encode".}
proc base64url_decode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                      outlen: ptr culong): cint {.importc: "base64url_decode".}
proc base64url_strict_decode*(`in`: ptr cuchar; len: culong; `out`: ptr cuchar;
                             outlen: ptr culong): cint {.
    importc: "base64url_strict_decode".}

##  ===> LTC_HKDF -- RFC5869 HMAC-based Key Derivation Function <===

proc hkdf_test*(): cint {.importc: "hkdf_test".}
proc hkdf_extract*(hash_idx: cint; salt: ptr cuchar; saltlen: culong;
                  `in`: ptr cuchar; inlen: culong; `out`: ptr cuchar;
                  outlen: ptr culong): cint {.importc: "hkdf_extract".}
proc hkdf_expand*(hash_idx: cint; info: ptr cuchar; infolen: culong; `in`: ptr cuchar;
                 inlen: culong; `out`: ptr cuchar; outlen: culong): cint {.
    importc: "hkdf_expand".}
proc hkdf*(hash_idx: cint; salt: ptr cuchar; saltlen: culong; info: ptr cuchar;
          infolen: culong; `in`: ptr cuchar; inlen: culong; `out`: ptr cuchar;
          outlen: culong): cint {.importc: "hkdf".}

##  ---- MEM routines ----

proc mem_neq*(a: pointer; b: pointer; len: csize): cint {.importc: "mem_neq".}
proc zeromem*(dst: pointer; len: csize) {.importc: "zeromem".}
proc burn_stack*(len: culong) {.importc: "burn_stack".}
proc error_to_string*(err: cint): cstring {.importc: "error_to_string".}
var crypt_build_settings* {.importc: "crypt_build_settings".}: cstring

##  ---- HMM ----

proc crypt_fsa*(mp: pointer): cint {.varargs, importc: "crypt_fsa".}
##  ---- Dynamic language support ----

proc crypt_get_constant*(namein: cstring; valueout: ptr cint): cint {.
    importc: "crypt_get_constant".}
proc crypt_list_all_constants*(names_list: cstring; names_list_size: ptr cuint): cint {.
    importc: "crypt_list_all_constants".}
proc crypt_get_size*(namein: cstring; sizeout: ptr cuint): cint {.
    importc: "crypt_get_size".}
proc crypt_list_all_sizes*(names_list: cstring; names_list_size: ptr cuint): cint {.
    importc: "crypt_list_all_sizes".}

proc init_LTM*() {.importc: "init_LTM".}

type
  adler32_state* {.bycopy.} = object
    s*: array[2, cushort]

proc adler32_init*(ctx: ptr adler32_state) {.importc: "adler32_init".}
proc adler32_update*(ctx: ptr adler32_state; input: ptr cuchar; length: culong) {.
    importc: "adler32_update".}
proc adler32_finish*(ctx: ptr adler32_state; hash: pointer; size: culong) {.
    importc: "adler32_finish".}
proc adler32_test*(): cint {.importc: "adler32_test".}

type
  crc32_state* {.bycopy.} = object
    crc*: uint32

proc crc32_init*(ctx: ptr crc32_state) {.importc: "crc32_init".}
proc crc32_update*(ctx: ptr crc32_state; input: ptr cuchar; length: culong) {.
    importc: "crc32_update".}
proc crc32_finish*(ctx: ptr crc32_state; hash: pointer; size: culong) {.
    importc: "crc32_finish".}
proc crc32_test*(): cint {.importc: "crc32_test".}

proc compare_testvector*(`is`: pointer; is_len: culong; should: pointer;
                        should_len: culong; what: cstring; which: cint): cint {.
    importc: "compare_testvector".}
