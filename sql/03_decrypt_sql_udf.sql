-- Use the following catalog
USE CATALOG <catalog>;

-- Use the following schema
USE SCHEMA <schema>;

-- Create the following UDF to encrypt
CREATE OR REPLACE FUNCTION decrypt_fpe(text STRING)
RETURNS STRING
DETERMINISTIC
LANGUAGE SQL
-- you may chose to specify functions from another schema
RETURN SELECT _encrypt_decrypt_fpe(
    key => secret(<scope>, <encryption secret key>),
    tweak => secret(<scope>, <tweak secret key>),
    text => text,
    operation => "DECRYPT"
);