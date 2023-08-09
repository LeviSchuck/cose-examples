# COSE Examples

I couldn't find examples of CBOR encoded COSE key objects in [COSE working 
group Examples](https://github.com/cose-wg/Examples).

Included in this repository are example test vectors for CBOR encoded COSE key objects.
These test vectors were created with [pycose](https://pycose.readthedocs.io/en/latest/).

Some odd modifications had to be done in the generation script `gen.py` as `pycose` lacks the ability to 
encode *public keys*. Also, it restricts symmetric keys to AES key lengths and did not support 
HMAC-SHA{384,512} key lengths. These missing features were compensated for by editing the CBOR structure 
and then re-encoding.

This work is released as public domain / Creative Commons Zero
