# python-fpe-cryptography

![GitHub License](https://img.shields.io/github/license/stikkireddy/python-fpe-cryptography)
![Build](https://github.com/stikkireddy/python-fpe-cryptography/actions/workflows/build.yaml/badge.svg)
[![codecov](https://codecov.io/github/stikkireddy/python-fpe-cryptography/branch/main/graph/badge.svg?token=EORUY66PNQ)](https://codecov.io/github/stikkireddy/python-fpe-cryptography)
![GitHub Tag](https://img.shields.io/github/v/tag/stikkireddy/python-fpe-cryptography?sort=semver&label=Latest%20Version)


Creates format preserving encryption using cryptography instead of pycryptodome. T
his is so you can cleanly run this in Databricks sql using UC functions.
Based off of https://github.com/mysto/python-fpe and ported to using cryptography AES ECB 
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB and if you want to 
learn more about fpe you can read this: https://github.com/mysto/python-fpe?tab=readme-ov-file#the-ff3-algorithm.

Example here by colleague Andrew Weaver: https://github.com/andyweaves/databricks-notebooks/blob/main/notebooks/privacy/format_preserving_encryption.py

This is a port of it into a python udf. You can find the ported code in fpe.py

## Using FPE as a python library with cryptography

### Using the FPE method

```python
import secrets
from ff3_cryptography.fpe import crypto_fpe_encrypt, crypto_fpe_decrypt

key = secrets.token_bytes(32).hex()
tweak = secrets.token_bytes(7).hex()

plaintext = '1234567890'
# these functions take care of the radix for you and have reasonable charsets and handle special chars
ciphertext = crypto_fpe_encrypt(key=key, tweak=tweak, input_text=plaintext)
decrypted = crypto_fpe_decrypt(key=key, tweak=tweak, input_text=ciphertext)

assert ciphertext != plaintext, "Encryption failed"
assert plaintext == decrypted, "Decryption failed"
```

### Using raw cipher object (not recommended if you dont know what you are doing)

Keep in mind you will need to modify the radix to match the data you are encrypting. Different char sets need 
different radix values. I recommend to use the solution provided by Andrew Weaver in the previous example.

```python
import secrets 
from ff3_cryptography.algo import FF3Cipher

key = secrets.token_bytes(32).hex()
tweak = secrets.token_bytes(7).hex()

plaintext = '1234567890'

ff3 = FF3Cipher(key, tweak, radix=10)
ciphertext = ff3.encrypt(plaintext)
decrypted = ff3.decrypt(ciphertext)

assert ciphertext != plaintext, "Encryption failed"
assert plaintext == decrypted, "Decryption failed"
```

## Using FPE in Databricks as UC Functions

Run this to create the function modify the catalog and schema as needed. The best practice for using this function in UC 
is to split it up into 3 or more functions. One for the python UDF that is private and meant to be used by sql functions designated 
with fixed encryption keys & tweak fetched from Databricks secrets. The python udf is meant to be private and designated 
by starting with `_`. Then you can call the python function by creating a sql function that calls the python function and 
fills in the encryption key and tweak using the `secret` sql function. Something like this:

```sql
CREATE OR REPLACE FUNCTION encrypt_fpe(text STRING, operation STRING)
RETURNS STRING
DETERMINISTIC
LANGUAGE SQL
-- you may chose to specify functions from another schema
RETURN SELECT_encrypt_decrypt_fpe(
    key => secret("my_scope", "my_encryption_key_hex"),
    tweak => secret("my_scope", "my_tweak_hex"),
    text => text,
    operation => "ENCRYPT"
);
```

Then you can use the `encrypt_fpe` function in your sql queries and likewise for decrypt. 

In more advanced settings you may have different strategies or different tweaks for different columns or rows designated 
in the sql function or in another table such that if two different users have the same data they can have different cipher 
text. 



Python UDF Functions (encrypt/decrypt private method)
* For a reference encrypt look at [01_python_udf.sql](sql/01_python_udf.sql).

SQL UDF Functions (encrypt/decrypt public functions with secrets injected)
* For a reference encrypt look at [02_encrypt_sql_udf.sql](sql/02_encrypt_sql_udf.sql).
* For a reference decrypt look at [03_decrypt_sql_udf.sql](sql/03_decrypt_sql_udf.sql).


### Using the private python function and messing with it.

#### Declare variables

You can pass keys in using sql secret commands. 

You can generate the key and tweak as hex using the following commands
```python
import secrets

# If needed generate a 256 bit key, store as a secret...
key = secrets.token_bytes(32).hex()

# If needed generate a 7 byte tweak, store as a secret...
tweak = secrets.token_bytes(7).hex()

print(key, tweak)
```

You can declare them this way or use databricks secrets to manage them.

```sql
DECLARE encryption_key="55bd9c16d82731fb15057fcb4bd10dddd385d679927355cec976dc1f956f0559";
DECLARE fpe_tweak="e333ac1b0ae092";
DECLARE plain_text="Hello world";
```

### Encrypt

```sql
SELECT main.default.encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    input_text => plain_text,
    operation => "ENCRYPT"
);
```

#### Create cipher text variable

```sql
DECLARE cipher_text STRING;
SET VAR cipher_text=(SELECT main.default.encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    text => plain_text,
    operation => "ENCRYPT"
));
```

#### Decrypt

```sql
SELECT main.default.encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    text => cipher_text,
    operation => "DECRYPT"
);
```

## Disclaimer
python-fpe-cryptography is not developed, endorsed not supported by Databricks. It is provided as-is; no warranty is derived from using this package. 
For more details, please refer to the license.