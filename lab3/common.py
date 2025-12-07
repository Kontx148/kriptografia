from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

from block_cipher.block_cipher import PaddingMode

DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000

BLOCK_CIPHER_PADDING = PaddingMode.SF

BLOCK_CIPHER_LIST_1 = ['AES CBC', 'AES ECB', 'AES CFB', 'AES OFB', 'VIG CBC', 'VIG ECB', 'VIG CFB', 'VIG OFB']
BLOCK_CIPHER_LIST_2 = ['VIG OFB']

def encode_public_key(key: RSAPublicKey) -> bytes:
    public_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes


def decode_public_key(data: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(data)

# RANDOM 256 CHAR LONG TEXT
# Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis,.


