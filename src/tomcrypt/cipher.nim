##  LibTomCrypt, modular cryptographic library -- Tom St Denis
##
##  LibTomCrypt is a library that provides various cryptographic
##  algorithms in a highly modular and flexible manner.
##
##  The library is free for all purposes without any express
##  guarantee it works.
##
##  ---- SYMMETRIC KEY STUFF -----
##
##  We put each of the ciphers scheduled keys in their own structs then we put all of
##  the key formats in one union.  This makes the function prototypes easier to use.
##

const LTC_BLOWFISH = 1
const LTC_RC5 = 1
const LTC_RC6 = 1
const LTC_SAFERP = 1
const LTC_RIJNDAEL = 1
const LTC_KSEED = 1
const LTC_KASUMI = 1
const LTC_XTEA = 1
const LTC_TWOFISH = 1
const LTC_SAFER = 1
const LTC_RC2 = 1
const LTC_DES = 1
const LTC_CAST5 = 1
const LTC_NOEKEON = 1
const LTC_SKIPJACK = 1
const LTC_KHAZAD = 1
const LTC_ANUBIS = 1
const LTC_MULTI2 = 1
const LTC_CAMELLIA = 1
const LTC_ECB_MODE = 1
const LTC_CFB_MODE = 1
const LTC_OFB_MODE = 1
const LTC_CBC_MODE = 1
const LTC_CTR_MODE = 1
const LTC_LRW_MODE = 1
const LTC_F8_MODE = 1
const LTC_XTS_MODE = 1
const LTC_CHACHA = 1
const LTC_RC4_STREAM = 1
const LTC_SOBER128_STREAM = 1

when declared(LTC_BLOWFISH):
  type
    blowfish_key* {.bycopy.} = object
      S*: array[4, array[256, ulong32]]
      K*: array[18, ulong32]

when declared(LTC_RC5):
  type
    rc5_key* {.bycopy.} = object
      rounds*: cint
      K*: array[50, ulong32]

when declared(LTC_RC6):
  type
    rc6_key* {.bycopy.} = object
      K*: array[44, ulong32]

when declared(LTC_SAFERP):
  type
    saferp_key* {.bycopy.} = object
      K*: array[33, array[16, cuchar]]
      rounds*: clong

when declared(LTC_RIJNDAEL):
  type
    rijndael_key* {.bycopy.} = object
      eK*: array[60, ulong32]
      dK*: array[60, ulong32]
      Nr*: cint

when declared(LTC_KSEED):
  type
    kseed_key* {.bycopy.} = object
      K*: array[32, ulong32]
      dK*: array[32, ulong32]

when declared(LTC_KASUMI):
  type
    kasumi_key* {.bycopy.} = object
      KLi1*: array[8, ulong32]
      KLi2*: array[8, ulong32]
      KOi1*: array[8, ulong32]
      KOi2*: array[8, ulong32]
      KOi3*: array[8, ulong32]
      KIi1*: array[8, ulong32]
      KIi2*: array[8, ulong32]
      KIi3*: array[8, ulong32]

when declared(LTC_XTEA):
  type
    xtea_key* {.bycopy.} = object
      A*: array[32, culong]
      B*: array[32, culong]

when declared(LTC_TWOFISH):
  when not defined(LTC_TWOFISH_SMALL):
    type
      twofish_key* {.bycopy.} = object
        S*: array[4, array[256, ulong32]]
        K*: array[40, ulong32]

  else:
    type
      twofish_key* {.bycopy.} = object
        K*: array[40, ulong32]
        S*: array[32, cuchar]
        start*: cuchar

when declared(LTC_SAFER):
  const
    LTC_SAFER_K64_DEFAULT_NOF_ROUNDS* = 6
    LTC_SAFER_K128_DEFAULT_NOF_ROUNDS* = 10
    LTC_SAFER_SK64_DEFAULT_NOF_ROUNDS* = 8
    LTC_SAFER_SK128_DEFAULT_NOF_ROUNDS* = 10
    LTC_SAFER_MAX_NOF_ROUNDS* = 13
    LTC_SAFER_BLOCK_LEN* = 8
    LTC_SAFER_KEY_LEN* = (
      1 + LTC_SAFER_BLOCK_LEN * (1 + 2 * LTC_SAFER_MAX_NOF_ROUNDS))
  type
    safer_block_t* = array[LTC_SAFER_BLOCK_LEN, cuchar]
    safer_key_t* = array[LTC_SAFER_KEY_LEN, cuchar]
  type
    safer_key* {.bycopy.} = object
      key*: safer_key_t

when declared(LTC_RC2):
  type
    rc2_key* {.bycopy.} = object
      xkey*: array[64, cuint]

when declared(LTC_DES):
  type
    des_key* {.bycopy.} = object
      ek*: array[32, ulong32]
      dk*: array[32, ulong32]

  type
    des3_key* {.bycopy.} = object
      ek*: array[3, array[32, ulong32]]
      dk*: array[3, array[32, ulong32]]

when declared(LTC_CAST5):
  type
    cast5_key* {.bycopy.} = object
      K*: array[32, ulong32]
      keylen*: ulong32

when declared(LTC_NOEKEON):
  type
    noekeon_key* {.bycopy.} = object
      K*: array[4, ulong32]
      dK*: array[4, ulong32]

when declared(LTC_SKIPJACK):
  type
    skipjack_key* {.bycopy.} = object
      key*: array[10, cuchar]

when declared(LTC_KHAZAD):
  type
    khazad_key* {.bycopy.} = object
      roundKeyEnc*: array[8 + 1, ulong64]
      roundKeyDec*: array[8 + 1, ulong64]

when declared(LTC_ANUBIS):
  type
    anubis_key* {.bycopy.} = object
      keyBits*: cint
      R*: cint
      roundKeyEnc*: array[18 + 1, array[4, ulong32]]
      roundKeyDec*: array[18 + 1, array[4, ulong32]]

when declared(LTC_MULTI2):
  type
    multi2_key* {.bycopy.} = object
      N*: cint
      uk*: array[8, ulong32]

when declared(LTC_CAMELLIA):
  type
    camellia_key* {.bycopy.} = object
      R*: cint
      kw*: array[4, ulong64]
      k*: array[24, ulong64]
      kl*: array[6, ulong64]

type
  symmetric_key* {.bycopy.} = object {.union.}
    des*: des_key
    des3*: des3_key
    rc2*: rc2_key
    safer*: safer_key
    twofish*: twofish_key
    blowfish*: blowfish_key
    rc5*: rc5_key
    rc6*: rc6_key
    saferp*: saferp_key
    rijndael*: rijndael_key
    xtea*: xtea_key
    cast5*: cast5_key
    noekeon*: noekeon_key
    skipjack*: skipjack_key
    khazad*: khazad_key
    anubis*: anubis_key
    kseed*: kseed_key
    kasumi*: kasumi_key
    multi2*: multi2_key
    camellia*: camellia_key
    data*: pointer


when declared(LTC_ECB_MODE):
  ## * A block cipher ECB structure
  type
    symmetric_ECB* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The scheduled key
      key*: symmetric_key

when declared(LTC_CFB_MODE):
  ## * A block cipher CFB structure
  type
    symmetric_CFB* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The padding offset
      padlen*: cint            ## * The current IV
      IV*: array[MAXBLOCKSIZE, cuchar] ## * The pad used to encrypt/decrypt
      pad*: array[MAXBLOCKSIZE, cuchar] ## * The scheduled key
      key*: symmetric_key

when declared(LTC_OFB_MODE):
  ## * A block cipher OFB structure
  type
    symmetric_OFB* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The padding offset
      padlen*: cint            ## * The current IV
      IV*: array[MAXBLOCKSIZE, cuchar] ## * The scheduled key
      key*: symmetric_key

when declared(LTC_CBC_MODE):
  ## * A block cipher CBC structure
  type
    symmetric_CBC* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The current IV
      IV*: array[MAXBLOCKSIZE, cuchar] ## * The scheduled key
      key*: symmetric_key

when declared(LTC_CTR_MODE):
  ## * A block cipher CTR structure
  type
    symmetric_CTR* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The padding offset
      padlen*: cint            ## * The mode (endianess) of the CTR, 0==little, 1==big
      mode*: cint              ## * counter width
      ctrlen*: cint            ## * The counter
      ctr*: array[MAXBLOCKSIZE, cuchar] ## * The pad used to encrypt/decrypt
      pad*: array[MAXBLOCKSIZE, cuchar] ## * The scheduled key
      key*: symmetric_key

when declared(LTC_LRW_MODE):
  ## * A LRW structure
  type
    symmetric_LRW* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen (must be a 128-bit block cipher)
      ## * The current IV
      IV*: array[16, cuchar]    ## * the tweak key
      tweak*: array[16, cuchar] ## * The current pad, it's the product of the first 15 bytes against the tweak key
      pad*: array[16, cuchar]   ## * The scheduled symmetric key
      key*: symmetric_key      ## * The pre-computed multiplication table
      PC*: array[16, array[256, array[16, cuchar]]]

when declared(LTC_F8_MODE):
  ## * A block cipher F8 structure
  type
    symmetric_F8* {.bycopy.} = object
      cipher*: cint            ## * The index of the cipher chosen
      ## * The block size of the given cipher
      blocklen*: cint          ## * The padding offset
      padlen*: cint            ## * The current IV
      IV*: array[MAXBLOCKSIZE, cuchar]
      MIV*: array[MAXBLOCKSIZE, cuchar] ## * Current block count
      blockcnt*: ulong32       ## * The scheduled key
      key*: symmetric_key

## * cipher descriptor table, last entry has "name == NULL" to mark the end of table

type
  ltc_cipher_descriptor* {.bycopy.} = object
    name*: cstring             ## * name of cipher
    ## * internal ID
    ID*: cuchar                ## * min keysize (octets)
    min_key_length*: cint      ## * max keysize (octets)
    max_key_length*: cint      ## * block size (octets)
    block_length*: cint        ## * default number of rounds
    default_rounds*: cint ## * Setup the cipher
                        ##       @param key         The input symmetric key
                        ##       @param keylen      The length of the input key (octets)
                        ##       @param num_rounds  The requested number of rounds (0==default)
                        ##       @param skey        [out] The destination of the scheduled key
                        ##       @return CRYPT_OK if successful
                        ##
    setup*: proc (key: ptr cuchar; keylen: cint; num_rounds: cint;
                skey: ptr symmetric_key): cint {.cdecl.} ## * Encrypt a block
                                           ##       @param pt      The plaintext
                                           ##       @param ct      [out] The ciphertext
                                           ##       @param skey    The scheduled key
                                           ##       @return CRYPT_OK if successful
                                           ##
    ecb_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint ## *
                                                                           ## Decrypt a block
                                                                           ##
                                                                           ## @param ct      The
                                                                           ## ciphertext
                                                                           ##
                                                                           ## @param pt      [out] The
                                                                           ## plaintext
                                                                           ##
                                                                           ## @param skey    The
                                                                           ## scheduled key
                                                                           ##
                                                                           ## @return
                                                                           ## CRYPT_OK if
                                                                           ## successful
                                                                           ##
    ecb_decrypt*: proc (ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint ## * Test the block
                                                                           ## cipher
                                                                           ##
                                                                           ## @return
                                                                           ## CRYPT_OK if
                                                                           ## successful,
                                                                           ## CRYPT_NOP if
                                                                           ## self-testing has been
                                                                           ## disabled
                                                                           ##
    test*: proc (): cint         ## * Terminate the context
                     ##       @param skey    The scheduled key
                     ##
    done*: proc (skey: ptr symmetric_key) ## * Determine a key size
                                     ##        @param keysize    [in/out] The size of the key desired and the suggested size
                                     ##        @return CRYPT_OK if successful
                                     ##
    keysize*: proc (keysize: ptr cint): cint ## * Accelerators *
                                       ## * Accelerated ECB encryption
                                       ##        @param pt      Plaintext
                                       ##        @param ct      Ciphertext
                                       ##        @param blocks  The number of complete blocks to process
                                       ##        @param skey    The scheduled key context
                                       ##        @return CRYPT_OK if successful
                                       ##
    accel_ecb_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; blocks: culong;
                            skey: ptr symmetric_key): cint ## * Accelerated ECB decryption
                                                       ##        @param pt      Plaintext
                                                       ##        @param ct      Ciphertext
                                                       ##        @param blocks  The number of complete blocks to process
                                                       ##        @param skey    The scheduled key context
                                                       ##        @return CRYPT_OK if successful
                                                       ##
    accel_ecb_decrypt*: proc (ct: ptr cuchar; pt: ptr cuchar; blocks: culong;
                            skey: ptr symmetric_key): cint ## * Accelerated CBC encryption
                                                       ##        @param pt      Plaintext
                                                       ##        @param ct      Ciphertext
                                                       ##        @param blocks  The number of complete blocks to process
                                                       ##        @param IV      The initial value (input/output)
                                                       ##        @param skey    The scheduled key context
                                                       ##        @return CRYPT_OK if successful
                                                       ##
    accel_cbc_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; blocks: culong;
                            IV: ptr cuchar; skey: ptr symmetric_key): cint ## * Accelerated CBC decryption
                                                                    ##        @param pt      Plaintext
                                                                    ##        @param ct      Ciphertext
                                                                    ##        @param blocks  The number of complete blocks to process
                                                                    ##        @param IV      The initial value
                                                                    ## (input/output)
                                                                    ##        @param skey    The scheduled key context
                                                                    ##        @return CRYPT_OK if successful
                                                                    ##
    accel_cbc_decrypt*: proc (ct: ptr cuchar; pt: ptr cuchar; blocks: culong;
                            IV: ptr cuchar; skey: ptr symmetric_key): cint ## * Accelerated CTR encryption
                                                                    ##        @param pt      Plaintext
                                                                    ##        @param ct      Ciphertext
                                                                    ##        @param blocks  The number of complete blocks to process
                                                                    ##        @param IV      The initial value
                                                                    ## (input/output)
                                                                    ##        @param mode    little or big endian counter (mode=0 or mode=1)
                                                                    ##        @param skey    The scheduled key context
                                                                    ##        @return CRYPT_OK if successful
                                                                    ##
    accel_ctr_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; blocks: culong;
                            IV: ptr cuchar; mode: cint; skey: ptr symmetric_key): cint ## *
                                                                              ## Accelerated
                                                                              ## LRW
                                                                              ##
                                                                              ## @param pt
                                                                              ## Plaintext
                                                                              ##
                                                                              ## @param ct
                                                                              ## Ciphertext
                                                                              ##
                                                                              ## @param
                                                                              ## blocks
                                                                              ## The
                                                                              ## number of
                                                                              ## complete
                                                                              ## blocks to
                                                                              ## process
                                                                              ##
                                                                              ## @param IV
                                                                              ## The
                                                                              ## initial
                                                                              ## value
                                                                              ## (input/output)
                                                                              ##
                                                                              ## @param
                                                                              ## tweak
                                                                              ## The
                                                                              ## LRW
                                                                              ## tweak
                                                                              ##
                                                                              ## @param
                                                                              ## skey
                                                                              ## The
                                                                              ## scheduled
                                                                              ## key
                                                                              ## context
                                                                              ##
                                                                              ## @return
                                                                              ## CRYPT_OK if
                                                                              ## successful
                                                                              ##
    accel_lrw_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; blocks: culong;
                            IV: ptr cuchar; tweak: ptr cuchar; skey: ptr symmetric_key): cint ##
                                                                                    ## *
                                                                                    ## Accelerated
                                                                                    ## LRW
                                                                                    ##
                                                                                    ## @param
                                                                                    ## ct
                                                                                    ## Ciphertext
                                                                                    ##
                                                                                    ## @param
                                                                                    ## pt
                                                                                    ## Plaintext
                                                                                    ##
                                                                                    ## @param
                                                                                    ## blocks
                                                                                    ## The
                                                                                    ## number
                                                                                    ## of
                                                                                    ## complete
                                                                                    ## blocks
                                                                                    ## to
                                                                                    ## process
                                                                                    ##
                                                                                    ## @param
                                                                                    ## IV
                                                                                    ## The
                                                                                    ## initial
                                                                                    ## value
                                                                                    ## (input/output)
                                                                                    ##
                                                                                    ## @param
                                                                                    ## tweak
                                                                                    ## The
                                                                                    ## LRW
                                                                                    ## tweak
                                                                                    ##
                                                                                    ## @param
                                                                                    ## skey
                                                                                    ## The
                                                                                    ## scheduled
                                                                                    ## key
                                                                                    ## context
                                                                                    ##
                                                                                    ## @return
                                                                                    ## CRYPT_OK
                                                                                    ## if
                                                                                    ## successful
                                                                                    ##
    accel_lrw_decrypt*: proc (ct: ptr cuchar; pt: ptr cuchar; blocks: culong;
                            IV: ptr cuchar; tweak: ptr cuchar; skey: ptr symmetric_key): cint ##
                                                                                    ## *
                                                                                    ## Accelerated
                                                                                    ## CCM
                                                                                    ## packet
                                                                                    ## (one-shot)
                                                                                    ##
                                                                                    ## @param
                                                                                    ## key
                                                                                    ## The
                                                                                    ## secret
                                                                                    ## key
                                                                                    ## to
                                                                                    ## use
                                                                                    ##
                                                                                    ## @param
                                                                                    ## keylen
                                                                                    ## The
                                                                                    ## length
                                                                                    ## of
                                                                                    ## the
                                                                                    ## secret
                                                                                    ## key
                                                                                    ## (octets)
                                                                                    ##
                                                                                    ## @param
                                                                                    ## uskey
                                                                                    ## A
                                                                                    ## previously
                                                                                    ## scheduled
                                                                                    ## key
                                                                                    ## [optional
                                                                                    ## can
                                                                                    ## be
                                                                                    ## NULL]
                                                                                    ##
                                                                                    ## @param
                                                                                    ## nonce
                                                                                    ## The
                                                                                    ## session
                                                                                    ## nonce
                                                                                    ## [use
                                                                                    ## once]
                                                                                    ##
                                                                                    ## @param
                                                                                    ## noncelen
                                                                                    ## The
                                                                                    ## length
                                                                                    ## of
                                                                                    ## the
                                                                                    ## nonce
                                                                                    ##
                                                                                    ## @param
                                                                                    ## header
                                                                                    ## The
                                                                                    ## header
                                                                                    ## for
                                                                                    ## the
                                                                                    ## session
                                                                                    ##
                                                                                    ## @param
                                                                                    ## headerlen
                                                                                    ## The
                                                                                    ## length
                                                                                    ## of
                                                                                    ## the
                                                                                    ## header
                                                                                    ## (octets)
                                                                                    ##
                                                                                    ## @param
                                                                                    ## pt
                                                                                    ## [out]
                                                                                    ## The
                                                                                    ## plaintext
                                                                                    ##
                                                                                    ## @param
                                                                                    ## ptlen
                                                                                    ## The
                                                                                    ## length
                                                                                    ## of
                                                                                    ## the
                                                                                    ## plaintext
                                                                                    ## (octets)
                                                                                    ##
                                                                                    ## @param
                                                                                    ## ct
                                                                                    ## [out]
                                                                                    ## The
                                                                                    ## ciphertext
                                                                                    ##
                                                                                    ## @param
                                                                                    ## tag
                                                                                    ## [out]
                                                                                    ## The
                                                                                    ## destination
                                                                                    ## tag
                                                                                    ##
                                                                                    ## @param
                                                                                    ## taglen
                                                                                    ## [in/out]
                                                                                    ## The
                                                                                    ## max
                                                                                    ## size
                                                                                    ## and
                                                                                    ## resulting
                                                                                    ## size
                                                                                    ## of
                                                                                    ## the
                                                                                    ## authentication
                                                                                    ## tag
                                                                                    ##
                                                                                    ## @param
                                                                                    ## direction
                                                                                    ## Encrypt
                                                                                    ## or
                                                                                    ## Decrypt
                                                                                    ## direction
                                                                                    ## (0
                                                                                    ## or
                                                                                    ## 1)
                                                                                    ##
                                                                                    ## @return
                                                                                    ## CRYPT_OK
                                                                                    ## if
                                                                                    ## successful
                                                                                    ##
    accel_ccm_memory*: proc (key: ptr cuchar; keylen: culong; uskey: ptr symmetric_key;
                           nonce: ptr cuchar; noncelen: culong; header: ptr cuchar;
                           headerlen: culong; pt: ptr cuchar; ptlen: culong;
                           ct: ptr cuchar; tag: ptr cuchar; taglen: ptr culong;
                           direction: cint): cint ## * Accelerated GCM packet (one shot)
                                               ##        @param key        The secret key
                                               ##        @param keylen     The length of the secret key
                                               ##        @param IV         The initialization vector
                                               ##        @param IVlen      The length of the initialization vector
                                               ##        @param adata      The additional authentication data (header)
                                               ##        @param adatalen   The length of the adata
                                               ##        @param pt         The plaintext
                                               ##        @param ptlen      The length of the plaintext (ciphertext length is the same)
                                               ##        @param ct         The ciphertext
                                               ##        @param tag        [out] The MAC tag
                                               ##        @param taglen     [in/out] The MAC tag length
                                               ##        @param direction  Encrypt or Decrypt mode (GCM_ENCRYPT or GCM_DECRYPT)
                                               ##        @return CRYPT_OK on success
                                               ##
    accel_gcm_memory*: proc (key: ptr cuchar; keylen: culong; IV: ptr cuchar;
                           IVlen: culong; adata: ptr cuchar; adatalen: culong;
                           pt: ptr cuchar; ptlen: culong; ct: ptr cuchar;
                           tag: ptr cuchar; taglen: ptr culong; direction: cint): cint ## *
                                                                              ## Accelerated
                                                                              ## one
                                                                              ## shot
                                                                              ## LTC_OMAC
                                                                              ##
                                                                              ## @param
                                                                              ## key
                                                                              ## The
                                                                              ## secret
                                                                              ## key
                                                                              ##
                                                                              ## @param
                                                                              ## keylen
                                                                              ## The
                                                                              ## key
                                                                              ## length
                                                                              ## (octets)
                                                                              ##
                                                                              ## @param in
                                                                              ## The
                                                                              ## message
                                                                              ##
                                                                              ## @param
                                                                              ## inlen
                                                                              ## Length of
                                                                              ## message
                                                                              ## (octets)
                                                                              ##
                                                                              ## @param
                                                                              ## out
                                                                              ## [out]
                                                                              ## Destination
                                                                              ## for
                                                                              ## tag
                                                                              ##
                                                                              ## @param
                                                                              ## outlen
                                                                              ## [in/out]
                                                                              ## Initial
                                                                              ## and
                                                                              ## final
                                                                              ## size of
                                                                              ## out
                                                                              ##
                                                                              ## @return
                                                                              ## CRYPT_OK on
                                                                              ## success
                                                                              ##
    omac_memory*: proc (key: ptr cuchar; keylen: culong; `in`: ptr cuchar; inlen: culong;
                      `out`: ptr cuchar; outlen: ptr culong): cint ## * Accelerated one shot XCBC
                                                            ##        @param key            The secret key
                                                            ##        @param keylen         The key length (octets)
                                                            ##        @param in             The message
                                                            ##        @param inlen          Length of message (octets)
                                                            ##        @param out            [out] Destination for tag
                                                            ##        @param outlen         [in/out] Initial and final size of out
                                                            ##        @return CRYPT_OK on success
                                                            ##
    xcbc_memory*: proc (key: ptr cuchar; keylen: culong; `in`: ptr cuchar; inlen: culong;
                      `out`: ptr cuchar; outlen: ptr culong): cint ## * Accelerated one shot F9
                                                            ##        @param key            The secret key
                                                            ##        @param keylen         The key length (octets)
                                                            ##        @param in             The message
                                                            ##        @param inlen          Length of message (octets)
                                                            ##        @param out            [out] Destination for tag
                                                            ##        @param outlen         [in/out] Initial and final size of out
                                                            ##        @return CRYPT_OK on success
                                                            ##        @remark Requires manual padding
                                                            ##
    f9_memory*: proc (key: ptr cuchar; keylen: culong; `in`: ptr cuchar; inlen: culong;
                    `out`: ptr cuchar; outlen: ptr culong): cint ## * Accelerated XTS encryption
                                                          ##        @param pt      Plaintext
                                                          ##        @param ct      Ciphertext
                                                          ##        @param blocks  The number of complete blocks to process
                                                          ##        @param tweak   The 128-bit encryption tweak (input/output).
                                                          ##                       The tweak should not be encrypted on input, but
                                                          ##                       next tweak will be copied encrypted on output.
                                                          ##        @param skey1   The first scheduled key context
                                                          ##        @param skey2   The second scheduled key context
                                                          ##        @return CRYPT_OK if successful
                                                          ##
    accel_xts_encrypt*: proc (pt: ptr cuchar; ct: ptr cuchar; blocks: culong;
                            tweak: ptr cuchar; skey1: ptr symmetric_key;
                            skey2: ptr symmetric_key): cint ## * Accelerated XTS decryption
                                                        ##         @param ct      Ciphertext
                                                        ##         @param pt      Plaintext
                                                        ##         @param blocks  The number of complete blocks to process
                                                        ##         @param tweak   The 128-bit encryption tweak (input/output).
                                                        ##                        The tweak should not be encrypted on input, but
                                                        ##                        next tweak will be copied encrypted on output.
                                                        ##         @param skey1   The first scheduled key context
                                                        ##         @param skey2   The second scheduled key context
                                                        ##         @return CRYPT_OK if successful
                                                        ##
    accel_xts_decrypt*: proc (ct: ptr cuchar; pt: ptr cuchar; blocks: culong;
                            tweak: ptr cuchar; skey1: ptr symmetric_key;
                            skey2: ptr symmetric_key): cint

var cipher_descriptor* {.importc: "cipher_descriptor", header:"tomcrypt.h".}: array[1_000_000, ltc_cipher_descriptor]

when declared(LTC_BLOWFISH):
  proc blowfish_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                      skey: ptr symmetric_key): cint {.importc: "blowfish_setup", header:"tomcrypt.h".}
  proc blowfish_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.
      importc: "blowfish_ecb_encrypt", header:"tomcrypt.h".}
  proc blowfish_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.
      importc: "blowfish_ecb_decrypt", header:"tomcrypt.h".}
  proc blowfish_test*(): cint {.importc: "blowfish_test", header:"tomcrypt.h".}
  proc blowfish_done*(skey: ptr symmetric_key) {.importc: "blowfish_done", header:"tomcrypt.h".}
  proc blowfish_keysize*(keysize: ptr cint): cint {.importc: "blowfish_keysize", header:"tomcrypt.h".}
  var blowfish_desc* {.importc: "blowfish_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_RC5):
  proc rc5_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                 skey: ptr symmetric_key): cint {.importc: "rc5_setup", header:"tomcrypt.h".}
  proc rc5_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc5_ecb_encrypt", header:"tomcrypt.h".}
  proc rc5_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc5_ecb_decrypt", header:"tomcrypt.h".}
  proc rc5_test*(): cint {.importc: "rc5_test", header:"tomcrypt.h".}
  proc rc5_done*(skey: ptr symmetric_key) {.importc: "rc5_done", header:"tomcrypt.h".}
  proc rc5_keysize*(keysize: ptr cint): cint {.importc: "rc5_keysize", header:"tomcrypt.h".}
  var rc5_desc* {.importc: "rc5_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_RC6):
  proc rc6_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                 skey: ptr symmetric_key): cint {.importc: "rc6_setup", header:"tomcrypt.h".}
  proc rc6_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc6_ecb_encrypt", header:"tomcrypt.h".}
  proc rc6_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc6_ecb_decrypt", header:"tomcrypt.h".}
  proc rc6_test*(): cint {.importc: "rc6_test", header:"tomcrypt.h".}
  proc rc6_done*(skey: ptr symmetric_key) {.importc: "rc6_done", header:"tomcrypt.h".}
  proc rc6_keysize*(keysize: ptr cint): cint {.importc: "rc6_keysize", header:"tomcrypt.h".}
  var rc6_desc* {.importc: "rc6_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_RC2):
  proc rc2_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                 skey: ptr symmetric_key): cint {.importc: "rc2_setup", header:"tomcrypt.h".}
  proc rc2_setup_ex*(key: ptr cuchar; keylen: cint; bits: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "rc2_setup_ex", header:"tomcrypt.h".}
  proc rc2_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc2_ecb_encrypt", header:"tomcrypt.h".}
  proc rc2_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rc2_ecb_decrypt", header:"tomcrypt.h".}
  proc rc2_test*(): cint {.importc: "rc2_test", header:"tomcrypt.h".}
  proc rc2_done*(skey: ptr symmetric_key) {.importc: "rc2_done", header:"tomcrypt.h".}
  proc rc2_keysize*(keysize: ptr cint): cint {.importc: "rc2_keysize", header:"tomcrypt.h".}
  var rc2_desc* {.importc: "rc2_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_SAFERP):
  proc saferp_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "saferp_setup", header:"tomcrypt.h".}
  proc saferp_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "saferp_ecb_encrypt", header:"tomcrypt.h".}
  proc saferp_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "saferp_ecb_decrypt", header:"tomcrypt.h".}
  proc saferp_test*(): cint {.importc: "saferp_test", header:"tomcrypt.h".}
  proc saferp_done*(skey: ptr symmetric_key) {.importc: "saferp_done", header:"tomcrypt.h".}
  proc saferp_keysize*(keysize: ptr cint): cint {.importc: "saferp_keysize", header:"tomcrypt.h".}
  var saferp_desc* {.importc: "saferp_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_SAFER):
  proc safer_k64_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                       skey: ptr symmetric_key): cint {.importc: "safer_k64_setup", header:"tomcrypt.h".}
  proc safer_sk64_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                        skey: ptr symmetric_key): cint {.importc: "safer_sk64_setup", header:"tomcrypt.h".}
  proc safer_k128_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                        skey: ptr symmetric_key): cint {.importc: "safer_k128_setup", header:"tomcrypt.h".}
  proc safer_sk128_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                         skey: ptr symmetric_key): cint {.importc: "safer_sk128_setup", header:"tomcrypt.h".}
  proc safer_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; key: ptr symmetric_key): cint {.importc: "safer_ecb_encrypt", header:"tomcrypt.h".}
  proc safer_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; key: ptr symmetric_key): cint {.importc: "safer_ecb_decrypt", header:"tomcrypt.h".}
  proc safer_k64_test*(): cint {.importc: "safer_k64_test", header:"tomcrypt.h".}
  proc safer_sk64_test*(): cint {.importc: "safer_sk64_test", header:"tomcrypt.h".}
  proc safer_sk128_test*(): cint {.importc: "safer_sk128_test", header:"tomcrypt.h".}
  proc safer_done*(skey: ptr symmetric_key) {.importc: "safer_done", header:"tomcrypt.h".}
  proc safer_64_keysize*(keysize: ptr cint): cint {.importc: "safer_64_keysize", header:"tomcrypt.h".}
  proc safer_128_keysize*(keysize: ptr cint): cint {.importc: "safer_128_keysize", header:"tomcrypt.h".}
  var
    safer_k64_desc* {.importc: "safer_k64_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    safer_k128_desc* {.importc: "safer_k128_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    safer_sk64_desc* {.importc: "safer_sk64_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    safer_sk128_desc* {.importc: "safer_sk128_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_RIJNDAEL):
  ##  make aes an alias
  template aes_setup*(params: varargs[untyped]): cint =
    rijndael_setup(params)
  template aes_ecb_encrypt*(params: varargs[untyped]): cint =
    rijndael_ecb_encrypt(params)
  template aes_ecb_decrypt*(params: varargs[untyped]): cint =
    rijndael_ecb_decrypt(params)
  template aes_test*(params: varargs[untyped]): cint =
    rijndael_test(params)
  template aes_done*(params: varargs[untyped]) =
    rijndael_done(params)
  template aes_keysize*(params: varargs[untyped]): cint =
    rijndael_keysize(params)
  template aes_enc_setup*(params: varargs[untyped]): cint =
    rijndael_enc_setup(params)
  template aes_enc_ecb_encrypt*(params: varargs[untyped]): cint =
    rijndael_enc_ecb_encrypt(params)
  template aes_enc_keysize*(params: varargs[untyped]): cint =
    rijndael_enc_keysize(params)
  proc rijndael_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                      skey: ptr symmetric_key): cint {.importc: "rijndael_setup", header:"tomcrypt.h".}
  proc rijndael_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rijndael_ecb_encrypt", header:"tomcrypt.h".}
  proc rijndael_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "rijndael_ecb_decrypt", header:"tomcrypt.h".}
  proc rijndael_test*(): cint {.importc: "rijndael_test", header:"tomcrypt.h".}
  proc rijndael_done*(skey: ptr symmetric_key) {.importc: "rijndael_done", header:"tomcrypt.h".}
  proc rijndael_keysize*(keysize: ptr cint): cint {.importc: "rijndael_keysize", header:"tomcrypt.h".}
  proc rijndael_enc_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                          skey: ptr symmetric_key): cint {.importc: "rijndael_enc_setup", header:"tomcrypt.h".}
  proc rijndael_enc_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar;
                                skey: ptr symmetric_key): cint {.importc: "rijndael_enc_ecb_encrypt", header:"tomcrypt.h".}
  proc rijndael_enc_done*(skey: ptr symmetric_key) {.importc: "rijndael_enc_done", header:"tomcrypt.h".}
  proc rijndael_enc_keysize*(keysize: ptr cint): cint {.importc: "rijndael_enc_keysize", header:"tomcrypt.h".}
  var
    rijndael_desc* {.importc: "rijndael_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    aes_desc* {.importc: "aes_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
  var
    rijndael_enc_desc* {.importc: "rijndael_enc_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    aes_enc_desc* {.importc: "aes_enc_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_XTEA):
  proc xtea_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                  skey: ptr symmetric_key): cint {.importc: "xtea_setup", header:"tomcrypt.h".}
  proc xtea_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "xtea_ecb_encrypt", header:"tomcrypt.h".}
  proc xtea_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "xtea_ecb_decrypt", header:"tomcrypt.h".}
  proc xtea_test*(): cint {.importc: "xtea_test", header:"tomcrypt.h".}
  proc xtea_done*(skey: ptr symmetric_key) {.importc: "xtea_done", header:"tomcrypt.h".}
  proc xtea_keysize*(keysize: ptr cint): cint {.importc: "xtea_keysize", header:"tomcrypt.h".}
  var xtea_desc* {.importc: "xtea_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_TWOFISH):
  proc twofish_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                     skey: ptr symmetric_key): cint {.importc: "twofish_setup", header:"tomcrypt.h".}
  proc twofish_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "twofish_ecb_encrypt", header:"tomcrypt.h".}
  proc twofish_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "twofish_ecb_decrypt", header:"tomcrypt.h".}
  proc twofish_test*(): cint {.importc: "twofish_test", header:"tomcrypt.h".}
  proc twofish_done*(skey: ptr symmetric_key) {.importc: "twofish_done", header:"tomcrypt.h".}
  proc twofish_keysize*(keysize: ptr cint): cint {.importc: "twofish_keysize", header:"tomcrypt.h".}
  var twofish_desc* {.importc: "twofish_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_DES):
  proc des_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                 skey: ptr symmetric_key): cint {.importc: "des_setup", header:"tomcrypt.h".}
  proc des_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "des_ecb_encrypt", header:"tomcrypt.h".}
  proc des_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "des_ecb_decrypt", header:"tomcrypt.h".}
  proc des_test*(): cint {.importc: "des_test", header:"tomcrypt.h".}
  proc des_done*(skey: ptr symmetric_key) {.importc: "des_done", header:"tomcrypt.h".}
  proc des_keysize*(keysize: ptr cint): cint {.importc: "des_keysize", header:"tomcrypt.h".}
  proc des3_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                  skey: ptr symmetric_key): cint {.importc: "des3_setup", header:"tomcrypt.h".}
  proc des3_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "des3_ecb_encrypt", header:"tomcrypt.h".}
  proc des3_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "des3_ecb_decrypt", header:"tomcrypt.h".}
  proc des3_test*(): cint {.importc: "des3_test", header:"tomcrypt.h".}
  proc des3_done*(skey: ptr symmetric_key) {.importc: "des3_done", header:"tomcrypt.h".}
  proc des3_keysize*(keysize: ptr cint): cint {.importc: "des3_keysize", header:"tomcrypt.h".}
  var
    des_desc* {.importc: "des_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
    des3_desc* {.importc: "des3_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_CAST5):
  proc cast5_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                   skey: ptr symmetric_key): cint {.importc: "cast5_setup", header:"tomcrypt.h".}
  proc cast5_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "cast5_ecb_encrypt", header:"tomcrypt.h".}
  proc cast5_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "cast5_ecb_decrypt", header:"tomcrypt.h".}
  proc cast5_test*(): cint {.importc: "cast5_test", header:"tomcrypt.h".}
  proc cast5_done*(skey: ptr symmetric_key) {.importc: "cast5_done", header:"tomcrypt.h".}
  proc cast5_keysize*(keysize: ptr cint): cint {.importc: "cast5_keysize", header:"tomcrypt.h".}
  var cast5_desc* {.importc: "cast5_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_NOEKEON):
  proc noekeon_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                     skey: ptr symmetric_key): cint {.importc: "noekeon_setup", header:"tomcrypt.h".}
  proc noekeon_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "noekeon_ecb_encrypt", header:"tomcrypt.h".}
  proc noekeon_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "noekeon_ecb_decrypt", header:"tomcrypt.h".}
  proc noekeon_test*(): cint {.importc: "noekeon_test", header:"tomcrypt.h".}
  proc noekeon_done*(skey: ptr symmetric_key) {.importc: "noekeon_done", header:"tomcrypt.h".}
  proc noekeon_keysize*(keysize: ptr cint): cint {.importc: "noekeon_keysize", header:"tomcrypt.h".}
  var noekeon_desc* {.importc: "noekeon_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_SKIPJACK):
  proc skipjack_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                      skey: ptr symmetric_key): cint {.importc: "skipjack_setup", header:"tomcrypt.h".}
  proc skipjack_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "skipjack_ecb_encrypt", header:"tomcrypt.h".}
  proc skipjack_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "skipjack_ecb_decrypt", header:"tomcrypt.h".}
  proc skipjack_test*(): cint {.importc: "skipjack_test", header:"tomcrypt.h".}
  proc skipjack_done*(skey: ptr symmetric_key) {.importc: "skipjack_done", header:"tomcrypt.h".}
  proc skipjack_keysize*(keysize: ptr cint): cint {.importc: "skipjack_keysize", header:"tomcrypt.h".}
  var skipjack_desc* {.importc: "skipjack_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_KHAZAD):
  proc khazad_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "khazad_setup", header:"tomcrypt.h".}
  proc khazad_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "khazad_ecb_encrypt", header:"tomcrypt.h".}
  proc khazad_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "khazad_ecb_decrypt", header:"tomcrypt.h".}
  proc khazad_test*(): cint {.importc: "khazad_test", header:"tomcrypt.h".}
  proc khazad_done*(skey: ptr symmetric_key) {.importc: "khazad_done", header:"tomcrypt.h".}
  proc khazad_keysize*(keysize: ptr cint): cint {.importc: "khazad_keysize", header:"tomcrypt.h".}
  var khazad_desc* {.importc: "khazad_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_ANUBIS):
  proc anubis_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "anubis_setup", header:"tomcrypt.h".}
  proc anubis_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "anubis_ecb_encrypt", header:"tomcrypt.h".}
  proc anubis_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "anubis_ecb_decrypt", header:"tomcrypt.h".}
  proc anubis_test*(): cint {.importc: "anubis_test", header:"tomcrypt.h".}
  proc anubis_done*(skey: ptr symmetric_key) {.importc: "anubis_done", header:"tomcrypt.h".}
  proc anubis_keysize*(keysize: ptr cint): cint {.importc: "anubis_keysize", header:"tomcrypt.h".}
  var anubis_desc* {.importc: "anubis_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_KSEED):
  proc kseed_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                   skey: ptr symmetric_key): cint {.importc: "kseed_setup", header:"tomcrypt.h".}
  proc kseed_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "kseed_ecb_encrypt", header:"tomcrypt.h".}
  proc kseed_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "kseed_ecb_decrypt", header:"tomcrypt.h".}
  proc kseed_test*(): cint {.importc: "kseed_test", header:"tomcrypt.h".}
  proc kseed_done*(skey: ptr symmetric_key) {.importc: "kseed_done", header:"tomcrypt.h".}
  proc kseed_keysize*(keysize: ptr cint): cint {.importc: "kseed_keysize", header:"tomcrypt.h".}
  var kseed_desc* {.importc: "kseed_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_KASUMI):
  proc kasumi_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "kasumi_setup", header:"tomcrypt.h".}
  proc kasumi_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "kasumi_ecb_encrypt", header:"tomcrypt.h".}
  proc kasumi_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "kasumi_ecb_decrypt", header:"tomcrypt.h".}
  proc kasumi_test*(): cint {.importc: "kasumi_test", header:"tomcrypt.h".}
  proc kasumi_done*(skey: ptr symmetric_key) {.importc: "kasumi_done", header:"tomcrypt.h".}
  proc kasumi_keysize*(keysize: ptr cint): cint {.importc: "kasumi_keysize", header:"tomcrypt.h".}
  var kasumi_desc* {.importc: "kasumi_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_MULTI2):
  proc multi2_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                    skey: ptr symmetric_key): cint {.importc: "multi2_setup", header:"tomcrypt.h".}
  proc multi2_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "multi2_ecb_encrypt", header:"tomcrypt.h".}
  proc multi2_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "multi2_ecb_decrypt", header:"tomcrypt.h".}
  proc multi2_test*(): cint {.importc: "multi2_test", header:"tomcrypt.h".}
  proc multi2_done*(skey: ptr symmetric_key) {.importc: "multi2_done", header:"tomcrypt.h".}
  proc multi2_keysize*(keysize: ptr cint): cint {.importc: "multi2_keysize", header:"tomcrypt.h".}
  var multi2_desc* {.importc: "multi2_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_CAMELLIA):
  proc camellia_setup*(key: ptr cuchar; keylen: cint; num_rounds: cint;
                      skey: ptr symmetric_key): cint {.importc: "camellia_setup", header:"tomcrypt.h".}
  proc camellia_ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "camellia_ecb_encrypt", header:"tomcrypt.h".}
  proc camellia_ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; skey: ptr symmetric_key): cint {.importc: "camellia_ecb_decrypt", header:"tomcrypt.h".}
  proc camellia_test*(): cint {.importc: "camellia_test", header:"tomcrypt.h".}
  proc camellia_done*(skey: ptr symmetric_key) {.importc: "camellia_done", header:"tomcrypt.h".}
  proc camellia_keysize*(keysize: ptr cint): cint {.importc: "camellia_keysize", header:"tomcrypt.h".}
  var camellia_desc* {.importc: "camellia_desc", header:"tomcrypt.h".}: ltc_cipher_descriptor
when declared(LTC_ECB_MODE):
  proc ecb_start*(cipher: cint; key: ptr cuchar; keylen: cint; num_rounds: cint;
                 ecb: ptr symmetric_ECB): cint {.importc: "ecb_start", header:"tomcrypt.h".}
  proc ecb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; ecb: ptr symmetric_ECB): cint {.importc: "ecb_encrypt", header:"tomcrypt.h".}
  proc ecb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; ecb: ptr symmetric_ECB): cint {.importc: "ecb_decrypt", header:"tomcrypt.h".}
  proc ecb_done*(ecb: ptr symmetric_ECB): cint {.importc: "ecb_done", header:"tomcrypt.h".}
when declared(LTC_CFB_MODE):
  proc cfb_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                 num_rounds: cint; cfb: ptr symmetric_CFB): cint {.importc: "cfb_start", header:"tomcrypt.h".}
  proc cfb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; cfb: ptr symmetric_CFB): cint {.importc: "cfb_encrypt", header:"tomcrypt.h".}
  proc cfb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; cfb: ptr symmetric_CFB): cint {.importc: "cfb_decrypt", header:"tomcrypt.h".}
  proc cfb_getiv*(IV: ptr cuchar; len: ptr culong; cfb: ptr symmetric_CFB): cint {.importc: "cfb_getiv", header:"tomcrypt.h".}
  proc cfb_setiv*(IV: ptr cuchar; len: culong; cfb: ptr symmetric_CFB): cint {.importc: "cfb_setiv", header:"tomcrypt.h".}
  proc cfb_done*(cfb: ptr symmetric_CFB): cint {.importc: "cfb_done", header:"tomcrypt.h".}
when declared(LTC_OFB_MODE):
  proc ofb_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                 num_rounds: cint; ofb: ptr symmetric_OFB): cint {.importc: "ofb_start", header:"tomcrypt.h".}
  proc ofb_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; ofb: ptr symmetric_OFB): cint {.importc: "ofb_encrypt", header:"tomcrypt.h".}
  proc ofb_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; ofb: ptr symmetric_OFB): cint {.importc: "ofb_decrypt", header:"tomcrypt.h".}
  proc ofb_getiv*(IV: ptr cuchar; len: ptr culong; ofb: ptr symmetric_OFB): cint {.importc: "ofb_getiv", header:"tomcrypt.h".}
  proc ofb_setiv*(IV: ptr cuchar; len: culong; ofb: ptr symmetric_OFB): cint {.importc: "ofb_setiv", header:"tomcrypt.h".}
  proc ofb_done*(ofb: ptr symmetric_OFB): cint {.importc: "ofb_done", header:"tomcrypt.h".}
when declared(LTC_CBC_MODE):
  proc cbc_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                 num_rounds: cint; cbc: ptr symmetric_CBC): cint {.importc: "cbc_start", header:"tomcrypt.h".}
  proc cbc_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; cbc: ptr symmetric_CBC): cint {.importc: "cbc_encrypt", header:"tomcrypt.h".}
  proc cbc_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; cbc: ptr symmetric_CBC): cint {.importc: "cbc_decrypt", header:"tomcrypt.h".}
  proc cbc_getiv*(IV: ptr cuchar; len: ptr culong; cbc: ptr symmetric_CBC): cint {.importc: "cbc_getiv", header:"tomcrypt.h".}
  proc cbc_setiv*(IV: ptr cuchar; len: culong; cbc: ptr symmetric_CBC): cint {.importc: "cbc_setiv", header:"tomcrypt.h".}
  proc cbc_done*(cbc: ptr symmetric_CBC): cint {.importc: "cbc_done", header:"tomcrypt.h".}
when declared(LTC_CTR_MODE):
  const
    CTR_COUNTER_LITTLE_ENDIAN* = 0x00000000
    CTR_COUNTER_BIG_ENDIAN* = 0x00001000
    LTC_CTR_RFC3686* = 0x00002000
  proc ctr_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                 num_rounds: cint; ctr_mode: cint; ctr: ptr symmetric_CTR): cint {.importc: "ctr_start", header:"tomcrypt.h".}
  proc ctr_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; ctr: ptr symmetric_CTR): cint {.importc: "ctr_encrypt", header:"tomcrypt.h".}
  proc ctr_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; ctr: ptr symmetric_CTR): cint {.importc: "ctr_decrypt", header:"tomcrypt.h".}
  proc ctr_getiv*(IV: ptr cuchar; len: ptr culong; ctr: ptr symmetric_CTR): cint {.importc: "ctr_getiv", header:"tomcrypt.h".}
  proc ctr_setiv*(IV: ptr cuchar; len: culong; ctr: ptr symmetric_CTR): cint {.importc: "ctr_setiv", header:"tomcrypt.h".}
  proc ctr_done*(ctr: ptr symmetric_CTR): cint {.importc: "ctr_done", header:"tomcrypt.h".}
  proc ctr_test*(): cint {.importc: "ctr_test", header:"tomcrypt.h".}
when declared(LTC_LRW_MODE):
  const
    LRW_ENCRYPT* = LTC_ENCRYPT
    LRW_DECRYPT* = LTC_DECRYPT
  proc lrw_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                 tweak: ptr cuchar; num_rounds: cint; lrw: ptr symmetric_LRW): cint {.importc: "lrw_start", header:"tomcrypt.h".}
  proc lrw_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; lrw: ptr symmetric_LRW): cint {.importc: "lrw_encrypt", header:"tomcrypt.h".}
  proc lrw_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; lrw: ptr symmetric_LRW): cint {.importc: "lrw_decrypt", header:"tomcrypt.h".}
  proc lrw_getiv*(IV: ptr cuchar; len: ptr culong; lrw: ptr symmetric_LRW): cint {.importc: "lrw_getiv", header:"tomcrypt.h".}
  proc lrw_setiv*(IV: ptr cuchar; len: culong; lrw: ptr symmetric_LRW): cint {.importc: "lrw_setiv", header:"tomcrypt.h".}
  proc lrw_done*(lrw: ptr symmetric_LRW): cint {.importc: "lrw_done", header:"tomcrypt.h".}
  proc lrw_test*(): cint {.importc: "lrw_test", header:"tomcrypt.h".}
  ##  don't call
  proc lrw_process*(pt: ptr cuchar; ct: ptr cuchar; len: culong; mode: cint;
                   lrw: ptr symmetric_LRW): cint {.importc: "lrw_process", header:"tomcrypt.h".}
when declared(LTC_F8_MODE):
  proc f8_start*(cipher: cint; IV: ptr cuchar; key: ptr cuchar; keylen: cint;
                salt_key: ptr cuchar; skeylen: cint; num_rounds: cint;
                f8: ptr symmetric_F8): cint {.importc: "f8_start", header:"tomcrypt.h".}
  proc f8_encrypt*(pt: ptr cuchar; ct: ptr cuchar; len: culong; f8: ptr symmetric_F8): cint {.importc: "f8_encrypt", header:"tomcrypt.h".}
  proc f8_decrypt*(ct: ptr cuchar; pt: ptr cuchar; len: culong; f8: ptr symmetric_F8): cint {.importc: "f8_decrypt", header:"tomcrypt.h".}
  proc f8_getiv*(IV: ptr cuchar; len: ptr culong; f8: ptr symmetric_F8): cint {.importc: "f8_getiv", header:"tomcrypt.h".}
  proc f8_setiv*(IV: ptr cuchar; len: culong; f8: ptr symmetric_F8): cint {.importc: "f8_setiv", header:"tomcrypt.h".}
  proc f8_done*(f8: ptr symmetric_F8): cint {.importc: "f8_done", header:"tomcrypt.h".}
  proc f8_test_mode*(): cint {.importc: "f8_test_mode", header:"tomcrypt.h".}
when declared(LTC_XTS_MODE):
  type
    symmetric_xts* {.bycopy.} = object
      key1*: symmetric_key
      key2*: symmetric_key
      cipher*: cint

  proc xts_start*(cipher: cint; key1: ptr cuchar; key2: ptr cuchar; keylen: culong;
                 num_rounds: cint; xts: ptr symmetric_xts): cint {.importc: "xts_start", header:"tomcrypt.h".}
  proc xts_encrypt*(pt: ptr cuchar; ptlen: culong; ct: ptr cuchar; tweak: ptr cuchar;
                   xts: ptr symmetric_xts): cint {.importc: "xts_encrypt", header:"tomcrypt.h".}
  proc xts_decrypt*(ct: ptr cuchar; ptlen: culong; pt: ptr cuchar; tweak: ptr cuchar;
                   xts: ptr symmetric_xts): cint {.importc: "xts_decrypt", header:"tomcrypt.h".}
  proc xts_done*(xts: ptr symmetric_xts) {.importc: "xts_done", header:"tomcrypt.h".}
  proc xts_test*(): cint {.importc: "xts_test", header:"tomcrypt.h".}
  proc xts_mult_x*(I: ptr cuchar) {.importc: "xts_mult_x", header:"tomcrypt.h".}
proc find_cipher*(name: cstring): cint {.importc: "find_cipher", header:"tomcrypt.h".}
proc find_cipher_any*(name: cstring; blocklen: cint; keylen: cint): cint {.importc: "find_cipher_any", header:"tomcrypt.h".}
proc find_cipher_id*(ID: cuchar): cint {.importc: "find_cipher_id", header:"tomcrypt.h".}
proc register_cipher*(cipher: ptr ltc_cipher_descriptor): cint {.importc: "register_cipher", header:"tomcrypt.h".}
proc unregister_cipher*(cipher: ptr ltc_cipher_descriptor): cint {.importc: "unregister_cipher", header:"tomcrypt.h".}
proc register_all_ciphers*(): cint {.importc: "register_all_ciphers", header:"tomcrypt.h".}
proc cipher_is_valid*(idx: cint): cint {.importc: "cipher_is_valid", header:"tomcrypt.h".}
##  ---- stream ciphers ----

when declared(LTC_CHACHA):
  type
    chacha_state* {.bycopy.} = object
      input*: array[16, ulong32]
      kstream*: array[64, cuchar]
      ksleft*: culong
      ivlen*: culong
      rounds*: cint

  proc chacha_setup*(st: ptr chacha_state; key: ptr cuchar; keylen: culong; rounds: cint): cint {.importc: "chacha_setup", header:"tomcrypt.h".}
  proc chacha_ivctr32*(st: ptr chacha_state; iv: ptr cuchar; ivlen: culong;
                      counter: ulong32): cint {.importc: "chacha_ivctr32", header:"tomcrypt.h".}
  proc chacha_ivctr64*(st: ptr chacha_state; iv: ptr cuchar; ivlen: culong;
                      counter: ulong64): cint {.importc: "chacha_ivctr64", header:"tomcrypt.h".}
  proc chacha_crypt*(st: ptr chacha_state; `in`: ptr cuchar; inlen: culong;
                    `out`: ptr cuchar): cint {.importc: "chacha_crypt", header:"tomcrypt.h".}
  proc chacha_keystream*(st: ptr chacha_state; `out`: ptr cuchar; outlen: culong): cint {.importc: "chacha_keystream", header:"tomcrypt.h".}
  proc chacha_done*(st: ptr chacha_state): cint {.importc: "chacha_done", header:"tomcrypt.h".}
  proc chacha_test*(): cint {.importc: "chacha_test", header:"tomcrypt.h".}
when declared(LTC_RC4_STREAM):
  type
    rc4_state* {.bycopy.} = object
      x*: cuint
      y*: cuint
      buf*: array[256, cuchar]

  proc rc4_stream_setup*(st: ptr rc4_state; key: ptr cuchar; keylen: culong): cint {.importc: "rc4_stream_setup", header:"tomcrypt.h".}
  proc rc4_stream_crypt*(st: ptr rc4_state; `in`: ptr cuchar; inlen: culong;
                        `out`: ptr cuchar): cint {.importc: "rc4_stream_crypt", header:"tomcrypt.h".}
  proc rc4_stream_keystream*(st: ptr rc4_state; `out`: ptr cuchar; outlen: culong): cint {.importc: "rc4_stream_keystream", header:"tomcrypt.h".}
  proc rc4_stream_done*(st: ptr rc4_state): cint {.importc: "rc4_stream_done", header:"tomcrypt.h".}
  proc rc4_stream_test*(): cint {.importc: "rc4_stream_test", header:"tomcrypt.h".}
when declared(LTC_SOBER128_STREAM):
  type
    sober128_state* {.bycopy.} = object
      R*: array[17, ulong32]    ##  Working storage for the shift register
      initR*: array[17, ulong32] ##  saved register contents
      konst*: ulong32          ##  key dependent constant
      sbuf*: ulong32           ##  partial word encryption buffer
      nbuf*: cint              ##  number of part-word stream bits buffered

  proc sober128_stream_setup*(st: ptr sober128_state; key: ptr cuchar; keylen: culong): cint {.importc: "sober128_stream_setup", header:"tomcrypt.h".}
  proc sober128_stream_setiv*(st: ptr sober128_state; iv: ptr cuchar; ivlen: culong): cint {.importc: "sober128_stream_setiv", header:"tomcrypt.h".}
  proc sober128_stream_crypt*(st: ptr sober128_state; `in`: ptr cuchar; inlen: culong;
                             `out`: ptr cuchar): cint {.importc: "sober128_stream_crypt", header:"tomcrypt.h".}
  proc sober128_stream_keystream*(st: ptr sober128_state; `out`: ptr cuchar;
                                 outlen: culong): cint {.importc: "sober128_stream_keystream", header:"tomcrypt.h".}
  proc sober128_stream_done*(st: ptr sober128_state): cint {.importc: "sober128_stream_done", header:"tomcrypt.h".}
  proc sober128_stream_test*(): cint {.importc: "sober128_stream_test", header:"tomcrypt.h".}
##  ref:         $Format:%D$
##  git commit:  $Format:%H$
##  commit time: $Format:%ai$
