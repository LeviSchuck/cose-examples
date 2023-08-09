from pycose.keys import CoseKey, EC2Key, OKPKey, SymmetricKey, RSAKey, keyops
from pycose.algorithms import RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, Ps256, Ps384, Ps512, HMAC256, HMAC384, HMAC512, EdDSA
from pycose.keys.curves import P256, P384, P521, Ed25519, Ed448, X25519, X448
import cbor2
from binascii import hexlify
from secrets import token_bytes
import os

def out(name, bytes):
    if not os.path.exists("./keys"):
        os.makedirs("./keys")
    
    path = f"./keys/{name}"

    if not os.path.exists(path):
        with open(path, "wb") as binary_file:
            binary_file.write(bytes)

algs = [
    ["RS256", RsaPkcs1Sha256],
    ["RS384", RsaPkcs1Sha384],
    ["RS512", RsaPkcs1Sha512],
    ["PS256", Ps256],
    ["PS384", Ps384],
    ["PS512", Ps512],
]

for [name, alg] in algs:
    cose_rsa_key = RSAKey.generate_key(2048)
    cose_rsa_key.kid = b"hello@example.com"
    cose_rsa_key.key_ops = [keyops.SignOp]
    cose_rsa_key.alg = alg
    # print(cose_rsa_key)

    out(f"{name}_private_key.bin", cose_rsa_key.encode())
    out(f"{name}_private_key.hex", hexlify(cose_rsa_key.encode()))

    cose_rsa_key2 : RSAKey = CoseKey.decode(cose_rsa_key.encode())
    # Force into a public key
    cose_rsa_key2.key_ops = [keyops.VerifyOp]
    cose_rsa_key3 = cbor2.loads(cose_rsa_key2.encode())
    del cose_rsa_key3[-3]
    del cose_rsa_key3[-4]
    del cose_rsa_key3[-6]
    del cose_rsa_key3[-7]
    del cose_rsa_key3[-8]

    out(f"{name}_public_key.bin", cbor2.dumps(cose_rsa_key3))
    out(f"{name}_public_key.hex", hexlify(cbor2.dumps(cose_rsa_key3)))

curves = [
    ["ES256", P256],
    ["ES384", P384],
    ["ES512", P521]
]

for [name, crv] in curves:
    ecdsa_key = EC2Key.generate_key(crv=crv)
    ecdsa_key.kid = b"hello@example.com"
    ecdsa_key.key_ops = [keyops.SignOp]
    # print(ecdsa_key)

    out(f"{name}_private_key.bin", ecdsa_key.encode())
    out(f"{name}_private_key.hex", hexlify(ecdsa_key.encode()))

    ecdsa_key2 : EC2Key = CoseKey.decode(ecdsa_key.encode())
    # Force into a public key
    ecdsa_key2.key_ops = [keyops.VerifyOp]
    ecdsa_key3 = cbor2.loads(ecdsa_key2.encode())
    del ecdsa_key3[-4]

    out(f"{name}_public_key.bin", cbor2.dumps(ecdsa_key3))
    out(f"{name}_public_key.hex", hexlify(cbor2.dumps(ecdsa_key3)))

hashes = [
    ["HS256", HMAC256],
    # https://github.com/TimothyClaeys/pycose/issues/112
    ["HS384", HMAC384],
    ["HS512", HMAC512]
]

for [name, alg] in hashes:
    key = SymmetricKey(token_bytes(32))
    key.kid = b"hello@example.com"
    key.key_ops = [keyops.MacCreateOp, keyops.MacVerifyOp]
    key.alg = HMAC256

    # Due to https://github.com/TimothyClaeys/pycose/issues/112
    # Forcefully rewriting key material.
    key = cbor2.loads(key.encode())
    if (alg != HMAC256):
        key[3] = alg.identifier
        key[-1] = token_bytes(alg.get_digest_length())

    out(f"{name}_symmetric_key.bin", cbor2.dumps(key))
    out(f"{name}_symmetric_key.hex", hexlify(cbor2.dumps(key)))

edwards = [
    ["ED25519", Ed25519],
    ["ED448", Ed448],
    ["X25519", X25519],
    ["X448", X448]
]

for [name, crv] in edwards:
    edwards_key = OKPKey.generate_key(crv)
    edwards_key.key_ops = [keyops.SignOp]
    out(f"{name}_private_key.bin", edwards_key.encode())
    out(f"{name}_private_key.hex", hexlify(edwards_key.encode()))

    edwards_key2 : EC2Key = CoseKey.decode(edwards_key.encode())
    # Force into a public key
    edwards_key2.key_ops = [keyops.VerifyOp]
    edwards_key3 = cbor2.loads(edwards_key2.encode())
    del edwards_key3[-4]

    out(f"{name}_public_key.bin", cbor2.dumps(edwards_key3))
    out(f"{name}_public_key.hex", hexlify(cbor2.dumps(edwards_key3)))
