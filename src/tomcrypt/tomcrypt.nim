import private/config

const
    CRYPT* = 0x0118
    SCRYPT* = "1.18.1"
    MAXBLOCKSIZE* = 128
    TAB_SIZE* = 32

type
    TomCryptErrorCode* = enum
       CRYPT_OK=0,               # Result OK
       CRYPT_ERROR,              # Generic Error
       CRYPT_NOP,                # Not a failure but no operation was performed
       CRYPT_INVALID_KEYSIZE,    # Invalid key size given
       CRYPT_INVALID_ROUNDS,     # Invalid number of rounds
       CRYPT_FAIL_TESTVECTOR,    # Algorithm failed test vectors
       CRYPT_BUFFER_OVERFLOW,    # Not enough space for output
       CRYPT_INVALID_PACKET,     # Invalid input packet given
       CRYPT_INVALID_PRNGSIZE,   # Invalid number of bits for a PRNG
       CRYPT_ERROR_READPRNG,     # Could not read enough from PRNG
       CRYPT_INVALID_CIPHER,     # Invalid cipher specified
       CRYPT_INVALID_HASH,       # Invalid hash specified
       CRYPT_INVALID_PRNG,       # Invalid PRNG specified
       CRYPT_MEM,                # Out of memory
       CRYPT_PK_TYPE_MISMATCH,   # Not equivalent types of PK keys
       CRYPT_PK_NOT_PRIVATE,     # Requires a private PK key
       CRYPT_INVALID_ARG,        # Generic invalid argument
       CRYPT_FILE_NOTFOUND,      # File Not Found
       CRYPT_PK_INVALID_TYPE,    # Invalid type of PK key
       CRYPT_OVERFLOW,           # An overflow of a value was detected/prevented
       CRYPT_UNUSED1,            # UNUSED1
       CRYPT_INPUT_TOO_LONG,     # The input was longer than expected.
       CRYPT_PK_INVALID_SIZE,    # Invalid size input for PK parameters
       CRYPT_INVALID_PRIME_SIZE, # Invalid size of prime requested
       CRYPT_PK_INVALID_PADDING, # Invalid padding on input
       CRYPT_HASH_OVERFLOW       # Hash applied to too many bits

include cfg
include cipher
include misc
