import secrets

from ff3_cryptography.fpe import crypto_fpe_decrypt, crypto_fpe_encrypt


def test_numeric_fpe():

    key = secrets.token_bytes(32).hex()
    tweak = secrets.token_bytes(7).hex()

    plaintext = "1234567890"
    ciphertext = crypto_fpe_encrypt(key=key, tweak=tweak, text=plaintext)
    decrypted = crypto_fpe_decrypt(key=key, tweak=tweak, text=ciphertext)

    assert ciphertext != plaintext, "Encryption failed"
    assert plaintext == decrypted, "Decryption failed"


def test_alpha_fpe():

    key = secrets.token_bytes(32).hex()
    tweak = secrets.token_bytes(7).hex()

    plaintext = "abcdefghij"
    ciphertext = crypto_fpe_encrypt(key=key, tweak=tweak, text=plaintext)
    decrypted = crypto_fpe_decrypt(key=key, tweak=tweak, text=ciphertext)

    assert ciphertext != plaintext, "Encryption failed"
    assert plaintext == decrypted, "Decryption failed"


def test_alphanum_fpe():

    key = secrets.token_bytes(32).hex()
    tweak = secrets.token_bytes(7).hex()

    plaintext = "abcdefghij123523565"
    ciphertext = crypto_fpe_encrypt(key=key, tweak=tweak, text=plaintext)
    decrypted = crypto_fpe_decrypt(key=key, tweak=tweak, text=ciphertext)

    assert ciphertext != plaintext, "Encryption failed"
    assert plaintext == decrypted, "Decryption failed"


def test_ascii_specialchars_fpe():

    key = secrets.token_bytes(32).hex()
    tweak = secrets.token_bytes(7).hex()

    plaintext = """abc35!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ """
    ciphertext = crypto_fpe_encrypt(key=key, tweak=tweak, text=plaintext)
    decrypted = crypto_fpe_decrypt(key=key, tweak=tweak, text=ciphertext)

    assert ciphertext != plaintext, "Encryption failed"
    assert plaintext == decrypted, "Decryption failed"
