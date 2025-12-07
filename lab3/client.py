from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from common import DEFAULT_PORT, DEFAULT_HOST

from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
import logging

from lab3.common import TransferDTO, ActionMode, encode_public_key, decode_public_key, ServerResponseDTO

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()


def generate_rsa_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


class Client:
    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    client_id: int
    client_socket: socket

    def __init__(self, client_id: int):
        self.client_id = client_id

        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((DEFAULT_HOST, DEFAULT_PORT))
        self.client_socket = clientSocket

    def __del__(self):
        self.client_socket.close()

    def send_dto(self, dto: TransferDTO):
        payload = dto.to_bytes()
        length = len(payload).to_bytes(4, 'big')
        self.client_socket.sendall(length + payload)

    def generate_and_register_key(self):
        logger.info('Generating RSA key pair...')
        self.private_key, self.public_key = generate_rsa_key_pair()
        logger.info('RSA key pair generated!')
        logger.info(f'Public key: {self.public_key}')

        data = f"{self.client_id}\n".encode() + encode_public_key(self.public_key)
        dto = TransferDTO(action=ActionMode.REGISTER_PUBLIC_KEY, data=data)

        logger.info('Sending DTO to server...')
        self.send_dto(dto)

        response = self.client_socket.recv(4096)
        response = ServerResponseDTO.from_bytes(response)
        if response.success:
            logger.info('RSA key pair registered successfully!')
        else:
            logger.error('Error registering RSA key pair!')

    def request_public_key(self, key_id: int):
        data = key_id.to_bytes(4, byteorder='big')
        dto = TransferDTO(action=ActionMode.REQUEST_PUBLIC_KEY, data=data)
        self.send_dto(dto)

        response = self.client_socket.recv(4096)
        response = ServerResponseDTO.from_bytes(response)
        if response.success:
            public_key = decode_public_key(response.data)
            logger.info(f'Public key for user {key_id}: {public_key}')
        else:
            logger.error(f'Error requesting public key for user {key_id} : {response.data.decode()}')

def print_help():
    print("=" * 40)
    print("Available commands:")
    print("1 - Generate and register RSA key pair")
    print("2 - Request public key from server")
    print("3 - Exit")


def run_communication():
    client_id = input("Please enter your client ID (this will be used for the port as well) = ")
    try:
        client_id = int(client_id)
    except ValueError:
        print("Client ID must be an integer")
        return

    logger.info('Client started, connecting to key_server...')
    client = Client(client_id)
    logger.info('Connected!')

    to_loop = True
    while to_loop:
        command = input("Enter command (help for list of commands): ")
        match command:
            case "1":
                client.generate_and_register_key()
            case "2":
                requested_id = input("Enter user ID to request public key for: ")
                client.request_public_key(int(requested_id))
            case "3":
                to_loop = False
            case _:
                print_help()


if __name__ == "__main__":
    run_communication()
