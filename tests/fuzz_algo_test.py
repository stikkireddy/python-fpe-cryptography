import functools
import multiprocessing
import random
import secrets
import string

import pytest
from ff3 import FF3Cipher as PyCryptodomeFF3Cipher

from ff3_cryptography.algo import FF3Cipher as CryptoFF3Cipher
from ff3_cryptography.fpe import fpe_encrypt_or_decrypt

crypto_encrypt_method = functools.partial(
    fpe_encrypt_or_decrypt, ff3_cipher_klass=CryptoFF3Cipher, operation="ENCRYPT"
)
pycryptodome_encrypt_method = functools.partial(
    fpe_encrypt_or_decrypt, ff3_cipher_klass=PyCryptodomeFF3Cipher, operation="ENCRYPT"
)
crypto_decrypt_method = functools.partial(
    fpe_encrypt_or_decrypt, ff3_cipher_klass=CryptoFF3Cipher, operation="DECRYPT"
)
pycryptodome_decrypt_method = functools.partial(
    fpe_encrypt_or_decrypt, ff3_cipher_klass=PyCryptodomeFF3Cipher, operation="DECRYPT"
)


def single_fuzz_test(iteration):
    # Generate a random key (256 bits)
    key = secrets.token_bytes(32).hex()

    # Generate a random tweak (56 bits)
    tweak = secrets.token_bytes(7).hex()

    charset = string.digits + string.ascii_lowercase + string.ascii_uppercase

    # Define plaintext length based on FF3 constraints (between 2 and 46)
    plaintext_length = random.randint(6, 46)
    plaintext = "".join(random.choices(charset, k=plaintext_length))

    pycryptodome_ciphertext = pycryptodome_encrypt_method(
        text=plaintext, key=key, tweak=tweak
    )
    crypto_ciphertext = crypto_encrypt_method(text=plaintext, key=key, tweak=tweak)

    assert (
        crypto_ciphertext == pycryptodome_ciphertext
    ), f"Iteration {iteration}: Encryption mismatch"

    crypto_decrypted = crypto_decrypt_method(
        text=crypto_ciphertext, key=key, tweak=tweak
    )
    pycryptodome_decrypted = pycryptodome_decrypt_method(
        text=pycryptodome_ciphertext, key=key, tweak=tweak
    )

    assert crypto_decrypted == pycryptodome_decrypted == plaintext, (
        f"Iteration {iteration}: Decryption mismatch, cryptography={crypto_decrypted} != pycryptodome={pycryptodome_decrypted} != plaintext={plaintext} "
        f"with ciphertext {crypto_ciphertext} and pycryptodome ciphertext {pycryptodome_ciphertext} with key {key} and tweak {tweak}"
    )

    if iteration % 1000 == 0:
        print(f"Iteration {iteration}: Test passed")


def test_error_too_long():
    with pytest.raises(ValueError) as e:
        key = secrets.token_bytes(32).hex()

        # Generate a random tweak (56 bits)
        tweak = secrets.token_bytes(7).hex()

        charset = string.digits + string.ascii_lowercase + string.ascii_uppercase

        # Define plaintext length based on FF3 constraints (between 2 and 32)
        plaintext_length = 47
        plaintext = "".join(random.choices(charset, k=plaintext_length))
        crypto_encrypt_method(text=plaintext, key=key, tweak=tweak)

    assert "not within max bounds" in str(e.value)


def test_error_too_short():
    with pytest.raises(ValueError) as e:
        key = secrets.token_bytes(32).hex()

        # Generate a random tweak (56 bits)
        tweak = secrets.token_bytes(7).hex()

        charset = string.digits + string.ascii_lowercase + string.ascii_uppercase

        # Define plaintext length based on FF3 constraints (between 2 and 32)
        plaintext_length = 2
        plaintext = "".join(random.choices(charset, k=plaintext_length))
        crypto_encrypt_method(text=plaintext, key=key, tweak=tweak)

    assert "not within minimum bounds" in str(e.value)


def test_fuzz_small():
    iterations = 1000  # Number of tests to run
    for i in range(iterations):
        single_fuzz_test(i)
    # with multiprocessing.Pool() as pool:
    #     pool.map(single_fuzz_test, range(iterations))


def test_fuzz_large():
    iterations = 10000  # Number of tests to run
    # for i in range(iterations):
    #     single_fuzz_test(i)
    with multiprocessing.Pool() as pool:
        pool.map(single_fuzz_test, range(iterations))
