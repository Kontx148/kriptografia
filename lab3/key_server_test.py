import threading
import logging
import unittest
from socket import *
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh

from lab3.common import *
from lab3.comm_utils import *

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

def generate_rsa_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def register_key(client_id, curr_socket, public_key):
    user_id_data = client_id.to_bytes(4, byteorder='big')
    data = user_id_data + b'\n' + encode_public_key(public_key)
    dto = TransferDTO(action=ActionMode.REGISTER_PUBLIC_KEY, data=data)
    send_transfer_dto(dto, curr_socket)

    resp = recv_response_dto(curr_socket)
    if not resp.success:
        raise AssertionError(f"Register failed: {resp.data!r}")

def request_public_key(key_id: int, curr_socket) -> RSAPublicKey | None:
    data = key_id.to_bytes(4, byteorder='big')
    dto = TransferDTO(action=ActionMode.REQUEST_PUBLIC_KEY, data=data)
    send_transfer_dto(dto, curr_socket)

    response = recv_response_dto(curr_socket)
    if response.success:
        public_key = decode_public_key(response.data)
        return public_key
    return None


class KeyServerUnitTest(unittest.TestCase):
    def setUp(self):
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((DEFAULT_HOST, DEFAULT_PORT))
        self.curr_socket = clientSocket

    def test_register_and_request(self, client_id: int = 999):
        private_key, public_key = generate_rsa_key_pair()
        register_key(client_id, self.curr_socket, public_key)
        fetched_public_key = request_public_key(client_id, self.curr_socket)
        self.assertEqual(public_key, fetched_public_key)

if __name__ == '__main__':
    unittest.main(verbosity=2)
