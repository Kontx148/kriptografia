import threading
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from socket import *
from cryptography.hazmat.primitives.asymmetric import rsa
import logging

from lab3.common import encode_public_key, decode_public_key
from common import DEFAULT_PORT, DEFAULT_HOST
from lab3.comm_utils import recv_transfer_dto, recv_response_dto, TransferDTO, ActionMode, ResponseDTO, \
    send_transfer_dto, send_response_dto

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
    _running = False
    listener: threading.Thread

    def __init__(self, client_id: int):
        self.client_id = client_id

        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((DEFAULT_HOST, DEFAULT_PORT))
        self.client_socket = clientSocket

    def run_listener(self):
        logger.info("Starting listener for client_id " + str(self.client_id) + "...")
        self.listener = threading.Thread(target=self._listen_loop, daemon=True)
        self.listener.start()
        self._running = True

    def stop_listener(self):
        logger.info("Stopping listener for client_id " + str(self.client_id) + "...")
        self.listener.join()
        self._running = False


    def _listen_loop(self):
        logger.info('Listener thread started')
        while self._running:
            response_dto = recv_response_dto(self.client_socket)
            if response_dto is None:
                logger.info('Server closed connection')
                break
            logger.info(f'Received DTO: {response_dto.data.decode()}')
        self._running = False
        logger.info('Listener thread stopped')

    def send_message(self, peer_port: int, message: str, action: ActionMode):
        """
        Sends a message to the specified peer port, using RSA encryption
        """
        logger.info(f'Sending message to peer {peer_port}: {message}')
        logger.info(f'Requesting public key for peer {peer_port}...')
        peer_public_key = self.request_public_key(peer_port)
        if peer_public_key is None:
            logger.error(f'Error requesting public key for peer {peer_port}')
            return

        peer_socket = socket(AF_INET, SOCK_STREAM)
        peer_socket.connect((DEFAULT_HOST, peer_port))

        dto = TransferDTO(action=action, data=message.encode())
        send_transfer_dto(dto, peer_socket)
        peer_socket.close()

    def __del__(self):
        self.client_socket.close()

    def generate_and_register_key(self):
        logger.info('Generating RSA key pair...')
        self.private_key, self.public_key = generate_rsa_key_pair()
        logger.info('RSA key pair generated!')
        logger.info(f'Public key: {self.public_key}')

        user_id_data = self.client_id.to_bytes(4, byteorder='big')
        data = user_id_data + b'\n' + encode_public_key(self.public_key)
        dto = TransferDTO(action=ActionMode.REGISTER_PUBLIC_KEY, data=data)

        logger.info('Sending DTO to server...')
        send_transfer_dto(dto, self.client_socket)

        # Don't wait for response if the listener is already running
        if self._running:
            return

        response = recv_response_dto(self.client_socket)
        if response.success:
            logger.info('RSA key pair registered successfully!')
        else:
            logger.error('Error registering RSA key pair!')

    def request_public_key(self, key_id: int) -> RSAPublicKey | None:
        data = key_id.to_bytes(4, byteorder='big')
        dto = TransferDTO(action=ActionMode.REQUEST_PUBLIC_KEY, data=data)
        send_transfer_dto(dto, self.client_socket)

        # Don't wait for a response if the listener is already running
        if self._running:
            return None

        response = recv_response_dto(self.client_socket)
        if response.success:
            public_key = decode_public_key(response.data)
            logger.info(f'Public key for user {key_id}: {public_key}')
            return public_key
        else:
            logger.error(f'Error requesting public key for user {key_id} : {response.data.decode()}')
        return None


def print_help():
    print("=" * 40)
    print("Available commands:")
    print("1 - Generate and register RSA key pair")
    print("2 - Request public key from server")
    print("3 - Exit")
    print("5 - Start listener")
    print("6 - Stop listener")


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
            case "5":
                client.run_listener()
            case "6":
                client.stop_listener()
            case _:
                print_help()


if __name__ == "__main__":
    run_communication()
