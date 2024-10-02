-- Use the following catalog
USE CATALOG <catalog>;

-- Use the following schema
USE SCHEMA <schema>;

-- Encrypt and decrypt internal python UDF
CREATE OR REPLACE FUNCTION _encrypt_decrypt_fpe(key STRING, tweak STRING, text STRING, operation STRING)
RETURNS STRING
DETERMINISTIC
LANGUAGE PYTHON
AS $$
# based on https://github.com/mysto/python-fpe/blob/main/ff3/ff3.py but ported to using cryptography
# instead of pycryptodome

# Package ff3 implements the FF3-1 format-preserving encryption algorithm/scheme

import logging
import math
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The recommendation in Draft SP 800-38G was strengthened to a requirement in Draft
# SP 800-38G Revision 1: the minimum domain size for FF1 and FF3-1 is one million.

NUM_ROUNDS = 8
BLOCK_SIZE = 16  # AES block size in bytes
TWEAK_LEN = 8  # Original FF3 tweak length
TWEAK_LEN_NEW = 7  # FF3-1 tweak length
HALF_TWEAK_LEN = TWEAK_LEN // 2

logger = logging.getLogger(__name__)


def reverse_bytes(data):
    """Reverse the bytes in the input data."""
    return data[::-1]


"""
FF3 encodes a string within a range of minLen..maxLen. The spec uses an alternating
Feistel with the following parameters:
    A fixed 128 bit block size
    128, 192 or 256 bit key length
    Cipher Block Chain (CBC-MAC) round function
    64-bit (FF3) or 56-bit (FF3-1)tweak
    eight (8) rounds
    Modulo addition

An encoded string representation of x is in the given integer base, which must be at
least 2. The result uses the lower-case letters 'a' to 'z' for digit values 10 to 35
and upper-case letters 'A' to 'Z' for digit values 36 to 61.

Instead of specifying the base, an alphabet may be specified as a string of unique
characters. For bases larger than 62, an explicit alphabet is mandatory.

FF3Cipher initializes a new FF3 Cipher object for encryption or decryption with key,
tweak and radix parameters. The default radix is 10, supporting encryption of decimal
numbers.

AES ECB is used as the cipher round value for XORing. ECB has a block size of 128 bits
(i.e 16 bytes) and is padded with zeros for blocks smaller than this size. ECB is used
only in encrypt mode to generate this XOR value. A Feistel decryption uses the same ECB
encrypt value to decrypt the text. XOR is trivially invertible when you know two of the
arguments.
"""


class FF3Cipher:
    """Class FF3Cipher implements the FF3 format-preserving encryption algorithm.

    If a value of radix between 2 and 62 is specified, then that many characters
    from the base 62 alphabet (digits + lowercase + uppercase latin) are used.
    """

    DOMAIN_MIN = 1_000_000  # 1M required in FF3-1
    BASE62 = string.digits + string.ascii_lowercase + string.ascii_uppercase
    BASE62_LEN = len(BASE62)
    RADIX_MAX = 256  # Support 8-bit alphabets for now

    def __init__(self, key, tweak, radix=10):
        keybytes = bytes.fromhex(key)
        self.key = reverse_bytes(keybytes)
        self.tweak = tweak
        self.radix = radix
        if radix <= FF3Cipher.BASE62_LEN:
            self.alphabet = FF3Cipher.BASE62[0:radix]
        else:
            self.alphabet = None

        # Calculate range of supported message lengths [minLen..maxLen]
        # per revised spec, radix^minLength >= 1,000,000.
        self.minLen = math.ceil(math.log(FF3Cipher.DOMAIN_MIN) / math.log(radix))

        # We simplify the specs log[radix](2^96) to 96/log2(radix) using the log base
        # change rule
        self.maxLen = 2 * math.floor(96 / math.log2(radix))

        klen = len(keybytes)

        # Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
        if klen not in (16, 24, 32):
            raise ValueError(
                f"key length is {klen} bytes but must be 128, 192, or 256 bits"
            )

        # While FF3 allows radices in [2, 2^16], commonly useful range is 2..62
        if (radix < 2) or (radix > FF3Cipher.RADIX_MAX):
            raise ValueError("radix must be between 2 and 256, inclusive")

        # Make sure 2 <= minLength <= maxLength
        if (self.minLen < 2) or (self.maxLen < self.minLen):
            raise ValueError("minLen or maxLen invalid, adjust your radix")

        # No need to initialize AES cipher here, as cryptography requires creating encryptors per use

    # factory method to create a FF3Cipher object with a custom alphabet
    @staticmethod
    def withCustomAlphabet(key, tweak, alphabet):
        c = FF3Cipher(key, tweak, len(alphabet))
        c.alphabet = alphabet
        return c

    def encrypt(self, plaintext):
        """Encrypts the plaintext string and returns a ciphertext of the same length
        and format"""
        return self.encrypt_with_tweak(plaintext, self.tweak)

    """
    Feistel structure

            u length |  v length
            A block  |  B block

                C <- modulo function

            B' <- C  |  A' <- B


    Steps:

    Let u = [n/2]
    Let v = n - u
    Let A = X[1..u]
    Let B = X[u+1,n]
    Let T(L) = T[0..31] and T(R) = T[32..63]
    for i <- 0..7 do
        If is even, let m = u and W = T(R) Else let m = v and W = T(L)
        Let P = REV([NUM<radix>(Rev(B))]^12 || W ⊗ REV(i^4)
        Let Y = CIPH(P)
        Let y = NUM<2>(REV(Y))
        Let c = (NUM<radix>(REV(A)) + y) mod radix^m
        Let C = REV(STR<radix>^m(c))
        Let A = B
        Let B = C
    end for
    Return A || B

    * Where REV(X) reverses the order of characters in the character string X

    See spec and examples:

    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf
    """

    # EncryptWithTweak allows a parameter tweak instead of the current Cipher's tweak

    def encrypt_with_tweak(self, plaintext, tweak):
        """Encrypts the plaintext string and returns a ciphertext of the same length
        and format"""
        tweakBytes = bytes.fromhex(tweak)

        n = len(plaintext)

        # Check if message length is within minLength and maxLength bounds
        if (n < self.minLen) or (n > self.maxLen):
            raise ValueError(
                f"message length {n} is not within min {self.minLen} and "
                f"max {self.maxLen} bounds"
            )

        # Make sure the length of tweak in bytes is 7 or 8 (56 or 64 bits)
        if len(tweakBytes) not in [TWEAK_LEN_NEW, TWEAK_LEN]:
            raise ValueError(
                f"tweak length {len(tweakBytes)} invalid: tweak must be "
                f"{TWEAK_LEN_NEW * 8} or {TWEAK_LEN * 8} bits"
            )

        # Todo: Check message is in current radix

        # Calculate split point
        u = math.ceil(n / 2)
        v = n - u

        # Split the message
        A = plaintext[:u]
        B = plaintext[u:]

        if len(tweakBytes) == TWEAK_LEN_NEW:
            # FF3-1
            tweakBytes = calculate_tweak64_ff3_1(tweakBytes)

        Tl = tweakBytes[:HALF_TWEAK_LEN]
        Tr = tweakBytes[HALF_TWEAK_LEN:]
        logger.debug(f"Tweak: {tweak}, tweakBytes:{tweakBytes.hex()}")

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether i is even or odd

        modU = self.radix**u
        modV = self.radix**v
        logger.debug(f"modU: {modU} modV: {modV}")

        # Main Feistel Round, 8 times
        #
        # AES ECB requires the number of bits in the plaintext to be a multiple of
        # the block size. Thus, we pad the input to 16 bytes

        for i in range(NUM_ROUNDS):
            # logger.debug(f"-------- Round {i}")
            # Determine alternating Feistel round side
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            # P is fixed-length 16 bytes
            P = calculate_p(i, self.alphabet, W, B)
            revP = reverse_bytes(P)

            S = aes_ecb_encrypt(self.key, revP)

            S = reverse_bytes(S)
            # logger.debug("S:    ", S.hex())

            y = int.from_bytes(S, byteorder="big")

            # Calculate c
            c = decode_int_r(A, self.alphabet)

            c = c + y

            if i % 2 == 0:
                c = c % modU
            else:
                c = c % modV

            # logger.debug(f"m: {m} A: {A} c: {c} y: {y}")
            C = encode_int_r(c, self.alphabet, int(m))

            # Final steps
            A = B
            B = C

            # logger.debug(f"A: {A} B: {B}")

        return A + B

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext string and returns a plaintext of the same length
        and format.

        The process of decryption is essentially the same as the encryption process.
        The  differences are  (1)  the  addition  function  is  replaced  by  a
        subtraction function that is its inverse, and (2) the order of the round
        indices (i) is reversed.
        """
        return self.decrypt_with_tweak(ciphertext, self.tweak)

    def decrypt_with_tweak(self, ciphertext, tweak):
        """Decrypts the ciphertext string and returns a plaintext of the same length
        and format"""
        tweakBytes = bytes.fromhex(tweak)

        n = len(ciphertext)

        # Check if message length is within minLength and maxLength bounds
        if (n < self.minLen) or (n > self.maxLen):
            raise ValueError(
                f"message length {n} is not within min {self.minLen} and "
                f"max {self.maxLen} bounds"
            )

        # Make sure the length of tweak in bytes is 7 or 8
        if len(tweakBytes) not in [TWEAK_LEN_NEW, TWEAK_LEN]:
            raise ValueError(
                f"tweak length {len(tweakBytes)} invalid: tweak must be 8 "
                f"bytes, or 56 bits"
            )

        # Todo: Check message is in current radix

        # Calculate split point
        u = math.ceil(n / 2)
        v = n - u

        # Split the message
        A = ciphertext[:u]
        B = ciphertext[u:]

        if len(tweakBytes) == TWEAK_LEN_NEW:
            # FF3-1
            tweakBytes = calculate_tweak64_ff3_1(tweakBytes)

        Tl = tweakBytes[:HALF_TWEAK_LEN]
        Tr = tweakBytes[HALF_TWEAK_LEN:]
        logger.debug(f"Tweak: {tweak}, tweakBytes:{tweakBytes.hex()}")

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether i is even or odd

        modU = self.radix**u
        modV = self.radix**v
        logger.debug(f"modU: {modU} modV: {modV}")

        # Main Feistel Round, 8 times

        for i in reversed(range(NUM_ROUNDS)):

            # logger.debug(f"-------- Round {i}")
            # Determine alternating Feistel round side
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl

            # P is fixed-length 16 bytes
            P = calculate_p(i, self.alphabet, W, A)
            revP = reverse_bytes(P)

            S = aes_ecb_encrypt(self.key, revP)
            S = reverse_bytes(S)

            # logger.debug("S:    ", S.hex())

            y = int.from_bytes(S, byteorder="big")

            # Calculate c
            c = decode_int_r(B, self.alphabet)

            c = c - y

            if i % 2 == 0:
                c = c % modU
            else:
                c = c % modV

            # logger.debug(f"m: {m} B: {B} c: {c} y: {y}")
            C = encode_int_r(c, self.alphabet, int(m))

            # Final steps
            B = A
            A = C

            # logger.debug(f"A: {A} B: {B}")

        return A + B


def aes_ecb_encrypt(key, data):
    """
    Encrypts data using AES ECB mode with the given key.

    :param key: The AES key as bytes.
    :param data: The plaintext data to encrypt as bytes. Must be exactly 16 bytes.
    :return: The ciphertext as bytes.
    """
    if len(data) != BLOCK_SIZE:
        raise ValueError(
            f"Data must be exactly {BLOCK_SIZE} bytes for AES ECB encryption"
        )
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def calculate_p(i, alphabet, W, B):
    # P is always 16 bytes
    P = bytearray(BLOCK_SIZE)

    # Calculate P by XORing W, i into the first 4 bytes of P
    # i only requires 1 byte, rest are 0 padding bytes
    # Anything XOR 0 is itself, so only need to XOR the last byte

    P[0] = W[0]
    P[1] = W[1]
    P[2] = W[2]
    P[3] = W[3] ^ int(i)  # Ensure i is within 0-255

    # The remaining 12 bytes of P are for rev(B) with padding

    BBytes = decode_int_r(B, alphabet).to_bytes(12, "big")
    # logger.debug(f"B: {B} BBytes: {BBytes.hex()}")

    P[BLOCK_SIZE - len(BBytes) :] = BBytes
    return P


def calculate_tweak64_ff3_1(tweak56):
    tweak64 = bytearray(8)
    tweak64[0] = tweak56[0]
    tweak64[1] = tweak56[1]
    tweak64[2] = tweak56[2]
    tweak64[3] = tweak56[3] & 0xF0
    tweak64[4] = tweak56[4]
    tweak64[5] = tweak56[5]
    tweak64[6] = tweak56[6]
    tweak64[7] = (tweak56[3] & 0x0F) << 4
    return bytes(tweak64)


def encode_int_r(n, alphabet, length=0):
    """
    Return a string representation of a number in the given base system for 2..256

    The string is left in a reversed order expected by the calling cryptographic
    function

    examples:
       encode_int_r(10, hexdigits)
        'A'
    """
    base = len(alphabet)
    if base > FF3Cipher.RADIX_MAX:
        raise ValueError(
            f"Base {base} is outside range of supported radix "
            f"2..{FF3Cipher.RADIX_MAX}"
        )

    x = ""
    while n >= base:
        n, b = divmod(n, base)
        x += alphabet[b]
    x += alphabet[n]

    if len(x) < length:
        x = x.ljust(length, alphabet[0])

    return x


def decode_int_r(astring, alphabet):
    """Decode a Base X encoded string into the number

    Arguments:
    - `astring`: The encoded string
    - `alphabet`: The alphabet to use for decoding
    """
    strlen = len(astring)
    base = len(alphabet)
    num = 0

    idx = 0
    try:
        for char in reversed(astring):
            power = strlen - (idx + 1)
            num += alphabet.index(char) * (base**power)
            idx += 1
    except ValueError:
        raise ValueError(f"char {char} not found in alphabet {alphabet}")

    return num


import functools
from typing import Literal


SPECIAL_CHAR_MODE = "REASSEMBLE"

# Define the character sets...
NUMERIC_CHARSET = "0123456789"
ALPA_CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHA_CHARSET_ALL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHANUMERIC_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_CHARSET = """0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"""
SPECIAL_CHARSET = """!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """


def _reassemble_string(input_str: str, positions: list, characters: str) -> str:
    # updated to do proper merge logic
    # prev code
    # for i in range(len(positions)):
    #     pos = positions[i]
    #     char = characters[i]
    #     input_str = input_str[:pos] + char + input_str[pos:]
    # after code
    # input_str will not have special characters and at the following positions will be the special characters
    # positions will be the positions of the special characters
    assert len(positions) == len(
        characters
    ), "Length of positions and characters must be equal"
    input_str_length = len(input_str)
    for i in range(len(positions)):
        pos = positions[i]
        char = characters[i]
        if pos < input_str_length:
            input_str = input_str[:pos] + char + input_str[pos:]
            input_str_length = len(input_str)
        elif pos == input_str_length:
            input_str = input_str + char
            input_str_length = len(input_str)
        else:
            raise ValueError(
                f"Position {pos} is out of bounds for string of length {input_str_length}"
            )

    return input_str


def _encrypt_or_decrypt(
    text: str,
    charset: str,
    operation: Literal["ENCRYPT", "DECRYPT"],
    key: str,
    tweak: str,
    ff3_cipher_klass: FF3Cipher,
) -> str:
    c = ff3_cipher_klass.withCustomAlphabet(key, tweak, charset)
    split_string = lambda string: (
        lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s
    )([string[i : i + 23] for i in range(0, len(string), 23)])

    if len(text) > 28:
        split = split_string(text)
        if operation == "ENCRYPT":
            output = "".join(list(map(lambda x: c.encrypt(x), split)))
        elif operation == "DECRYPT":
            output = "".join(list(map(lambda x: c.decrypt(x), split)))
        else:
            raise NotImplementedError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
    else:
        if operation == "ENCRYPT":
            output = c.encrypt(text)
        elif operation == "DECRYPT":
            output = c.decrypt(text)
        else:
            raise NotImplementedError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
    return output


def _encrypt_or_decrypt_alpha(
    text: str,
    operation: Literal["ENCRYPT", "DECRYPT"],
    key: str,
    tweak: str,
    ff3_cipher_klass: FF3Cipher,
) -> str:
    if text.isupper():
        return _encrypt_or_decrypt(
            text, ALPA_CHARSET_UPPER, operation, key, tweak, ff3_cipher_klass
        )
    elif text.islower():
        return _encrypt_or_decrypt(
            text, ALPHA_CHARSET_LOWER, operation, key, tweak, ff3_cipher_klass
        )
    else:
        return _encrypt_or_decrypt(
            text, ALPHA_CHARSET_ALL, operation, key, tweak, ff3_cipher_klass
        )


def _encrypt_or_decrypt_by_type(
    text: str,
    operation: Literal["ENCRYPT", "DECRYPT"],
    key: str,
    tweak: str,
    ff3_cipher_klass: FF3Cipher,
) -> str:
    if text.isnumeric():
        return _encrypt_or_decrypt(
            text, NUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass
        )
    elif text.isalnum():
        return _encrypt_or_decrypt(
            text, ALPHANUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass
        )
    else:
        raise ValueError(f"text: {text} should be either numeric or alphanumeric")


def fpe_encrypt_or_decrypt(
    *,
    text: str,  # can be cipher text or plaintext depending on operation
    operation: Literal["ENCRYPT", "DECRYPT"],
    key: str,
    tweak: str,
    ff3_cipher_klass: FF3Cipher,
) -> str:
    if len(text) < 6:
        raise ValueError(
            f"Input string length {len(text)} is not within minimum bounds: 6"
        )

    if len(text) >= 47:
        raise ValueError(f"Input length is {len(text)} is not within max bounds of: 47")

    if text.isnumeric():
        return _encrypt_or_decrypt(
            text, NUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass
        )

    elif text.isalnum():
        return _encrypt_or_decrypt(
            text, ALPHANUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass
        )

    # should never really be reached as the above two conditions should cover all cases
    # elif text.isalpha():
    #     return _encrypt_or_decrypt_alpha(text, operation, key, tweak, ff3_cipher_klass)

    elif text.isascii():

        import re

        if SPECIAL_CHAR_MODE == "TOKENIZE":
            return _encrypt_or_decrypt(
                text, ASCII_CHARSET, operation, key, tweak, ff3_cipher_klass
            )
        elif SPECIAL_CHAR_MODE == "REASSEMBLE":
            extract_special_chars = lambda string: (
                [char for char in re.findall(r"[^a-zA-Z0-9]", string)],
                [i for i, char in enumerate(string) if char in SPECIAL_CHARSET],
            )
            characters, positions = extract_special_chars(text)
            removed = re.sub("([^a-zA-Z0-9])", "", text)
            encrypted_decrypted = _encrypt_or_decrypt_by_type(
                removed, operation, key, tweak, ff3_cipher_klass
            )
            reassembled = _reassemble_string(encrypted_decrypted, positions, characters)
            return reassembled
        else:
            raise NotImplementedError(
                "Invalid option - must be 'TOKENIZE' or 'REASSEMBLE'"
            )


crypto_fpe_encrypt_or_decrypt = functools.partial(
    fpe_encrypt_or_decrypt, ff3_cipher_klass=FF3Cipher
)

crypto_fpe_encrypt = functools.partial(
    fpe_encrypt_or_decrypt, operation="ENCRYPT", ff3_cipher_klass=FF3Cipher
)
crypto_fpe_decrypt = functools.partial(
    fpe_encrypt_or_decrypt, operation="DECRYPT", ff3_cipher_klass=FF3Cipher
)


if operation == "ENCRYPT":
    return crypto_fpe_encrypt_or_decrypt(text=text, operation="ENCRYPT", key=key, tweak=tweak)
elif operation == "DECRYPT":
    return crypto_fpe_encrypt_or_decrypt(text=text, operation="DECRYPT", key=key, tweak=tweak)
else:
    raise ValueError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
$$;
