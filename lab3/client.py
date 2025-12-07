from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from common import DEFAULT_PORT, DEFAULT_HOST

from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging

from lab3.common import TransferDTO, ActionMode

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()

def init_connection() -> socket:
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((DEFAULT_HOST, DEFAULT_PORT))
    return clientSocket

def generate_rsa_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def run_communication():
    client_id = input("Please enter your client ID (this will be used for the port as well) = ")
    try:
        client_id = int(client_id)
    except ValueError:
        print("Client ID must be an integer")
        return

    logger.info('Client started, connecting to key_server...')
    clientSocket = init_connection()
    logger.info('Connected!')
    logger.info('Generating RSA key pair...')
    private_key, public_key = generate_rsa_key_pair()
    logger.info('RSA key pair generated!')

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    data = f"{client_id}\n".encode() + public_bytes

    dto = TransferDTO(action=ActionMode.REGISTER_PUBLIC_KEY, data=data)

    logger.info('Sending DTO to server...')
    clientSocket.sendall(dto.to_bytes())

    response = clientSocket.recv(4096)
    logger.info(f'From Server: {response!r}')

    clientSocket.close()

if __name__ == "__main__":
    run_communication()