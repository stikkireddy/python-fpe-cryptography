import functools
from typing import Literal

from ff3_cryptography.algo import FF3Cipher

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
