import secrets

from ff3 import FF3Cipher as PyCryptodomeFF3Cipher

from ff3_cryptography.algo import FF3Cipher as CryptoFF3Cipher


def test_basic():
    key = secrets.token_bytes(32).hex()
    tweak = secrets.token_bytes(7).hex()

    plaintext = "1234567890"

    ff3 = CryptoFF3Cipher(key, tweak, radix=10)
    ciphertext = ff3.encrypt(plaintext)
    decrypted = ff3.decrypt(ciphertext)

    assert ciphertext != plaintext, "Encryption failed"
    assert plaintext == decrypted, "Decryption failed"


def test_equals_pycryptodome_impl():
    # If needed generate a 256 bit key, store as a secret...
    key = secrets.token_bytes(32).hex()

    # If needed generate a 7 byte tweak, store as a secret...
    tweak = secrets.token_bytes(7).hex()

    plaintext = "1234567890"

    crypto_ff3 = CryptoFF3Cipher(key, tweak)
    pycryptodome_ff3 = PyCryptodomeFF3Cipher(key, tweak)

    crypto_ciphertext = crypto_ff3.encrypt(plaintext)
    pycryptodome_ciphertext = pycryptodome_ff3.encrypt(plaintext)

    assert crypto_ciphertext == pycryptodome_ciphertext, "Encryption failed"

    crypto_decrypted = crypto_ff3.decrypt(crypto_ciphertext)
    pycryptodome_decrypted = pycryptodome_ff3.decrypt(pycryptodome_ciphertext)

    assert crypto_decrypted == pycryptodome_decrypted == plaintext, "Decryption failed"
