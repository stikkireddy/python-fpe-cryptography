import functools

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


def reassemble_string(input_str: str, positions: list, characters: str) -> str:
    for i in range(len(positions)):
        pos = positions[i]
        char = characters[i]
        input_str = input_str[:pos] + char + input_str[pos:]
    return input_str


def encrypt_or_decrypt(text: str, charset: str, operation: str, key: str, tweak: str,
                       ff3_cipher_klass: FF3Cipher) -> str:
    c = ff3_cipher_klass.withCustomAlphabet(key, tweak, charset)
    split_string = lambda string: (lambda s: s[:-1] + [s[-2] + s[-1]] if len(s[-1]) < 4 else s)(
        [string[i:i + 23] for i in range(0, len(string), 23)])

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


def encrypt_or_decrypt_alpha(text: str, operation: str, key: str, tweak: str, ff3_cipher_klass: FF3Cipher) -> str:
    if text.isupper():
        return encrypt_or_decrypt(text, ALPA_CHARSET_UPPER, operation, key, tweak, ff3_cipher_klass)
    elif text.islower():
        return encrypt_or_decrypt(text, ALPHA_CHARSET_LOWER, operation, key, tweak, ff3_cipher_klass)
    else:
        return encrypt_or_decrypt(text, ALPHA_CHARSET_ALL, operation, key, tweak, ff3_cipher_klass)

def encrypt_or_decrypt_by_type(text: str, operation: str, key: str, tweak: str, ff3_cipher_klass: FF3Cipher) -> str:
    if text.isnumeric():
        return encrypt_or_decrypt(text, NUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass)
    elif text.isalnum():
        return encrypt_or_decrypt(text, ALPHANUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass)
    else:
        return encrypt_or_decrypt_alpha(text, operation, key, tweak, ff3_cipher_klass)

def fpe_encrypt_or_decrypt(text: str, operation: str, key: str, tweak: str, ff3_cipher_klass: FF3Cipher) -> str:
    if len(text) < 6:
        raise ValueError(f"Input string length {len(text)} is not within minimum bounds: 6")

    if len(text) >= 47:
        raise ValueError(f"Input length is {len(text)} is not within max bounds of: 47")

    if text.isnumeric():
        return encrypt_or_decrypt(text, NUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass)

    elif text.isalnum():
        return encrypt_or_decrypt(text, ALPHANUMERIC_CHARSET, operation, key, tweak, ff3_cipher_klass)

    elif text.isalpha():
        return encrypt_or_decrypt_alpha(text, operation, key, tweak, ff3_cipher_klass)

    elif text.isascii():

        import re
        if SPECIAL_CHAR_MODE == "TOKENIZE":
            return encrypt_or_decrypt(text, ASCII_CHARSET, operation, key, tweak, ff3_cipher_klass)
        elif SPECIAL_CHAR_MODE == "REASSEMBLE":
            extract_special_chars = lambda string: ([char for char in re.findall(r"[^\w]", string)],
                                                    [i for i, char in enumerate(string) if char in SPECIAL_CHARSET])
            characters, positions = extract_special_chars(text)
            removed = re.sub("([^a-zA-Z0-9])", "", text)
            encrypted_decrypted = encrypt_or_decrypt_by_type(removed, operation, key, tweak, ff3_cipher_klass)
            reassembled = reassemble_string(encrypted_decrypted, positions, characters)
            return reassembled
        else:
            raise NotImplementedError("Invalid option - must be 'TOKENIZE' or 'REASSEMBLE'")


crypto_fpe_encrypt_or_decrypt = functools.partial(fpe_encrypt_or_decrypt, ff3_cipher_klass=FF3Cipher)