from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000


def encode_public_key(key: RSAPublicKey) -> bytes:
    public_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes


def decode_public_key(data: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(data)



