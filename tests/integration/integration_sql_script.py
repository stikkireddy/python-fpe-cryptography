if __name__ == "__main__":
    import ff3_cryptography.algo
    import ff3_cryptography.fpe

    with open(ff3_cryptography.algo.__file__, "r") as f:
        ALGO_CODE = f.read()

    with open(ff3_cryptography.fpe.__file__, "r") as f:
        lines = f.readlines()
        FPE_CODE = "".join(
            [line for line in lines if not line.startswith("from ff3_cryptography.")]
        )

    FUNCTION_SQL = f"""
CREATE OR REPLACE FUNCTION _encrypt_decrypt_fpe(key STRING, tweak STRING, text STRING, operation STRING)
RETURNS STRING
DETERMINISTIC
LANGUAGE PYTHON
AS $$
{ALGO_CODE}

{FPE_CODE}

if operation == "ENCRYPT":
    return crypto_fpe_encrypt_or_decrypt(text=text, operation="ENCRYPT", key=key, tweak=tweak)
elif operation == "DECRYPT":
    return crypto_fpe_encrypt_or_decrypt(text=text, operation="DECRYPT", key=key, tweak=tweak)
else:
    raise ValueError("Invalid option - must be 'ENCRYPT' or 'DECRYPT'")
$$;
"""

    print(FUNCTION_SQL)

    sql = f"""-- Use the following catalog
USE CATALOG main;

-- Use the following schema
USE SCHEMA default;

-- Create the encrypt/decrypt function
{FUNCTION_SQL}

-- Create variables
DECLARE encryption_key="55bd9c16d82731fb15057fcb4bd10dddd385d679927355cec976dc1f956f0559";
DECLARE fpe_tweak="e333ac1b0ae092";
DECLARE plain_text="Hello world";


SELECT main.default._encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    text => plain_text,
    operation => "ENCRYPT"
);

-- Create cipher text variable
DECLARE cipher_text STRING;
SET VAR cipher_text=(SELECT main.default._encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    text => plain_text,
    operation => "ENCRYPT"
));

SELECT main.default._encrypt_decrypt_fpe(
    key => encryption_key,
    tweak => fpe_tweak,
    text => cipher_text,
    operation => "DECRYPT"
);
"""
    with open("integration_sql_test.sql", "w") as f:
        f.write(sql)
