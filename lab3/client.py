import json
import threading
import logging
from socket import *
from typing import Tuple, List

from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey, DHPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key

from lab1.crypto import encrypt_vigenere_bytes, decrypt_vigenere_bytes
from lab3.common import *
from lab3.comm_utils import *
from common import DEFAULT_PORT, DEFAULT_HOST

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()


def generate_rsa_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


class Client:
    """
    Client for communicating with key server and other clients
    """
    private_key: RSAPrivateKey
    public_key: RSAPublicKey
    client_id: int
    client_socket: socket
    _running = False
    listener: threading.Thread

    shared_key: bytes | None = None
    block_cipher: BlockCipher | None = None

    def __init__(self, client_id: int):
        self.client_id = client_id

        # Init connection with the key_server
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((DEFAULT_HOST, DEFAULT_PORT))
        self.client_socket = clientSocket

    # Listener actions
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

        # Don't wait for a response if the listener is already running
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
            logger.info(f'Public key for peer {key_id}: {public_key}')
            return public_key
        else:
            logger.error(f'Error requesting public key for peer {key_id} : {response.data.decode()}')
        return None

    def open_listener_socket(self):
        # Open a new socket for listening
        listen_socket = socket(AF_INET, SOCK_STREAM)
        listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        listen_socket.bind(('', self.client_id))
        listen_socket.listen(1)

        if self._running:
            self.stop_listener()

        return listen_socket

    def request_peer_public_key(self, peer_id: int) -> RSAPublicKey | None:
        logger.info("Requesting public RSA key for peer " + str(peer_id) + "...")
        dto = TransferDTO(action=ActionMode.REQUEST_PUBLIC_KEY, data=peer_id.to_bytes(4, byteorder='big'))
        send_transfer_dto(dto, self.client_socket)
        response = recv_response_dto(self.client_socket)
        if not response.success:
            logger.error(f'Error requesting public key for peer {peer_id} : {response.data.decode()}')
            raise ValueError(
                "Error requesting public key for peer " + str(peer_id) + ": " + response.data.decode() + "")

        logger.info(f'Successfully requested public key for peer {peer_id}')
        return decode_public_key(response.data)

    def request_half_key(self) -> DHPrivateKey | None:
        logger.info("Requesting half secret for peer " + str(self.client_id) + "...")
        dto = TransferDTO(action=ActionMode.REQUEST_HALF_SECRET, data=b'')
        send_transfer_dto(dto, self.client_socket)
        response = recv_response_dto(self.client_socket)
        if not response.success:
            logger.error(f'Error requesting half secret for peer {self.client_id} : {response.data.decode()}')
            raise ValueError(
                "Error requesting half secret for peer " + str(self.client_id) + ": " + response.data.decode() + "")

        logger.info(f'Successfully received secret for peer {self.client_id}')
        dh_private_key = load_pem_private_key(response.data, password=None)
        return dh_private_key

    def send_block_cipher(self, block_cipher_list: list[str], peer_public_key: RSAPublicKey, peer_socket: socket):
        logger.info('Sending block cipher list to peer using RSA encryption...')
        encrypted_data = json.dumps(block_cipher_list).encode()
        encrypted_data = peer_public_key.encrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        dto = TransferDTO(action=ActionMode.SENDING_BLOCK_CIPHER, data=encrypted_data)
        send_transfer_dto(dto, peer_socket)
        logger.info("Successfully sent block cipher list to peer")

    def receive_block_cipher(self, peer_socket: socket) -> List[str] | None:
        logger.info('Waiting for block cipher list from other peer ...')

        response = recv_transfer_dto(peer_socket)
        if response is None:
            logger.error('Error receiving peer-to-peer request from another client')
            return None

        if response.action != ActionMode.SENDING_BLOCK_CIPHER:
            logger.error(f'Received unexpected action {response.action} from client')
            return None

        try:
            # Decrypt the encrypted payload with our own RSA private key
            decrypted_bytes = self.private_key.decrypt(
                response.data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # The decrypted data should be a JSON-encoded list of block ciphers
            block_ciphers = json.loads(decrypted_bytes.decode())

            logger.info(f'Received block cipher list of length {len(block_ciphers)}: from other peer')
            return block_ciphers

        except Exception as e:
            logger.exception(f'Failed to decrypt or parse block cipher list: {e}')
            return None

    def send_half_secret(self, key: DHPublicKey, peer_public_key: RSAPublicKey, peer_socket: socket):
        """
        Sends a half-secret to the specified peer port, using RSA encryption
        """
        # Serialize a DH public key to bytes
        logger.info('Sending half secret to peer using RSA encryption...')
        dh_public_bytes = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Encrypt with a peer's RSA public key
        encrypted_data = peer_public_key.encrypt(
            dh_public_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        dto = TransferDTO(action=ActionMode.SENDING_HALF_SECRET, data=encrypted_data)
        send_transfer_dto(dto, peer_socket)
        logger.info("Successfully sent half secret to peer")

    def receive_half_secret(self, peer_socket: socket) -> DHPublicKey | None:
        logger.info("Waiting for half secret from peer ...")

        response = recv_transfer_dto(peer_socket)
        if response is None:
            logger.error('Error receiving peer-to-peer request from another peer')
            return None

        if response.action != ActionMode.SENDING_HALF_SECRET:
            logger.error(f'Received unexpected action {response.action} from peer')

        try:
            # Decrypt using our RSA private key
            decrypted = self.private_key.decrypt(
                response.data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Load the DH public key from decrypted bytes
            peer_dh_public_key = load_der_public_key(decrypted)
            if not isinstance(peer_dh_public_key, dh.DHPublicKey):
                logger.error('Decrypted key is not a DHPublicKey')
                return None

            logger.info("Successfully received half secret from peer")
            return peer_dh_public_key

        except Exception as e:
            logger.exception(f'Failed to decrypt or load peer half secret: {e}')
            return None

    def find_common_cipher(self, block_cipher_list_1: List[str], block_cipher_list_2: List[str]) -> str | None:
        common_cipher = None
        for cipher in block_cipher_list_1:
            if cipher in block_cipher_list_2:
                common_cipher = cipher
                break

        if common_cipher is None:
            logger.error("No common block cipher found between peers")
            return None
        logger.info("Common block cipher found : " + common_cipher)
        return common_cipher

    def handle_first_peer_communication(self, peer_port: int):
        # Fixed the block cipher list
        block_cipher_list_1 = BLOCK_CIPHER_LIST_1

        listener_socket = self.open_listener_socket()

        # First, open a new socket for the peer
        peer_socket = socket(AF_INET, SOCK_STREAM)
        peer_socket.connect((DEFAULT_HOST, peer_port))

        # Send a peer-to-peer request, sending our client ID
        user_id_data = self.client_id.to_bytes(4, byteorder='big')
        dto = TransferDTO(ActionMode.REQUEST_PEER_TO_PEER_COMMUNICATION, user_id_data)
        logger.info(f'Sending peer-to-peer request to peer {peer_port}...')
        send_transfer_dto(dto, peer_socket)

        # Wait for the peer to connect back to our listening socket
        logger.info('Waiting for peer to connect back with accept/decline response...')
        conn, addr = listener_socket.accept()
        response = recv_response_dto(conn)
        if response is None:
            logger.error(f'Error receiving peer-to-peer response from peer {peer_port}')
            return
        if not response.success:
            logger.info(f'Peer {peer_port} rejected peer-to-peer communication request')
            return
        logger.info(f'Peer {peer_port} accepted peer-to-peer communication request')


        # Request peer's public key
        client2_public_key = self.request_peer_public_key(peer_port)

        # Send a block cipher list to peer
        self.send_block_cipher(block_cipher_list_1, client2_public_key, peer_socket)

        # Waiting for the block cipher list from a client
        block_cipher_list_2 = self.receive_block_cipher(conn)

        # Find the first matching element in the lists
        common_cipher = self.find_common_cipher(block_cipher_list_1, block_cipher_list_2)
        if common_cipher is None:
            return

        # Generate half secret
        key1 = self.request_half_key()

        # Send this key1 to client2 with rsa
        self.send_half_secret(key1.public_key(), client2_public_key, peer_socket)

        # Receive half-secret from client2 with rsa
        key2 = self.receive_half_secret(conn)

        # Compute the shared key
        shared = key1.exchange(key2)

        logger.info("Successfully created common key : " + shared.hex())

        # Save the shared key and init blockCipher
        self.shared_key = shared
        self._init_block_cipher_with_shared_key(common_cipher)

        # Start a chat loop (initiator sends first)
        self.chat_loop_initiator(peer_socket, conn)
        listener_socket.close()
        return

    def handle_second_peer_communication(self):
        # Fixed the block cipher list
        block_cipher_list_2 = BLOCK_CIPHER_LIST_2

        listener_socket = self.open_listener_socket()

        # Wait for a peer-to-peer request from another client
        logger.info('Waiting for peer-to-peer request from another peer...')

        conn, addr = listener_socket.accept()
        response = recv_transfer_dto(conn)
        if response is None:
            logger.error('Error receiving peer-to-peer request from another peer')
            return
        if response.action != ActionMode.REQUEST_PEER_TO_PEER_COMMUNICATION:
            logger.error(f'Received unexpected action {response.action} from peer {addr}')
            return
        client1_id = int.from_bytes(response.data, 'big')
        logger.info(f'Received peer-to-peer request from peer {client1_id}')

        # Accept or decline the request
        accept = input(f'Accept peer-to-peer request from peer {client1_id}? (y/n): \n')
        declined = accept not in ['y', 'Y']
        if accept == 'y':
            logger.info(f'Accepting peer-to-peer request from peer {client1_id}')
            response = ResponseDTO(True, b'')
        else:
            logger.info(f'Declining peer-to-peer request from peer {client1_id}')
            response = ResponseDTO(False, b'')

        # Open a new socket for the peer
        peer_socket = socket(AF_INET, SOCK_STREAM)
        peer_socket.connect((DEFAULT_HOST, client1_id))
        send_response_dto(response, peer_socket)

        if declined:
            return
        logger.info("peer-to-peer communication established with peer " + str(client1_id) + "")

        # Request peer's public key
        client1_public_key = self.request_peer_public_key(client1_id)

        # Waiting for the block cipher list from client 1
        block_cipher_list_1 = self.receive_block_cipher(conn)

        # Send a block cipher list to peer
        self.send_block_cipher(block_cipher_list_2, client1_public_key, peer_socket)

        # Find the first matching element in the lists
        common_cipher = self.find_common_cipher(block_cipher_list_2, block_cipher_list_1)
        if common_cipher is None:
            return

            # Generate half secret
        key2 = self.request_half_key()

        # Receive half-secret from client1 using rsa
        key1 = self.receive_half_secret(conn)

        # Send key2 to client1 using rsa
        self.send_half_secret(key2.public_key(), client1_public_key, peer_socket)

        # Compute the shared key
        shared = key2.exchange(key1)
        logger.info("Successfully created common key : " + shared.hex())

        # Save the shared key and init blockCipher

        self.shared_key = shared
        self._init_block_cipher_with_shared_key(common_cipher)

        # Start a chat loop (receiver waits for the first message)
        self.chat_loop_receiver(peer_socket, conn)
        listener_socket.close()
        return

    def _init_block_cipher_with_shared_key(self, common_cipher: str):
        """
        Initialize self.block_cipher using self.shared_key as a string key.
        Truncates/pads the hex string to exactly 16 characters
        """
        if self.shared_key is None:
            logger.error("No shared key available")
            return

        # Convert shared bytes to hex string
        key_str = self.shared_key.hex()

        # AES-128 needs exactly 16 bytes after .encode()
        if len(key_str) < 16:
            key_str = key_str.ljust(16, '0')
        key_str = key_str[:16]

        match common_cipher:
            case "AES CBC":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.CBC, BLOCK_CIPHER_PADDING,
                                                encrypt_aes_bytes, decrypt_aes_bytes, )
            case "AES ECB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.ECB, BLOCK_CIPHER_PADDING,
                                                encrypt_aes_bytes, decrypt_aes_bytes, )
            case "AES CFB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.CFB, BLOCK_CIPHER_PADDING,
                                                encrypt_aes_bytes, decrypt_aes_bytes)
            case "AES OFB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.OFB, BLOCK_CIPHER_PADDING,
                                                encrypt_aes_bytes, decrypt_aes_bytes)
            case "VIG CBC":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.CBC, BLOCK_CIPHER_PADDING,
                                                encrypt_vigenere_bytes, decrypt_vigenere_bytes)
            case "VIG ECB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.ECB, BLOCK_CIPHER_PADDING,
                                                encrypt_vigenere_bytes, decrypt_vigenere_bytes)
            case "VIG CFB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.CFB, BLOCK_CIPHER_PADDING,
                                                encrypt_vigenere_bytes, decrypt_vigenere_bytes)
            case "VIG OFB":
                self.block_cipher = BlockCipher(len(key_str) * 8, key_str, None, CipherMode.OFB, BLOCK_CIPHER_PADDING,
                                                encrypt_vigenere_bytes, decrypt_vigenere_bytes)

    def chat_loop_initiator(self, peer_socket: socket, conn: socket):
        """
        Encrypted chat for the client who initiated the key exchange (sends first).
        Type 'stop' to send 'goodbye' and end.
        """
        if self.block_cipher is None:
            logger.error("BlockCipher not initialized.")
            return

        logger.info("Starting encrypted chat (you send first). Type 'stop' to end.")

        running = True
        while running:
            msg = input("You: ")
            if msg.strip().lower() == "stop":
                plaintext = b"goodbye"
            else:
                plaintext = msg.encode()

            encrypted = self.block_cipher.encrypt(plaintext)
            dto = TransferDTO(action=ActionMode.CHAT_MESSAGE, data=encrypted)
            send_transfer_dto(dto, peer_socket)

            if msg.strip().lower() == "stop":
                logger.info("Sent goodbye. Ending chat.")
                break

            response = recv_transfer_dto(conn)
            if response is None:
                logger.info("Peer closed connection.")
                break
            if response.action != ActionMode.CHAT_MESSAGE:
                logger.error(f"Unexpected action: {response.action}")
                break

            try:
                decrypted = self.block_cipher.decrypt(response.data, remove_padding=True)
                text = decrypted.decode(errors="replace")
            except Exception as e:
                logger.exception(f"Decryption error: {e}")
                break

            if text.strip().lower() == "goodbye":
                logger.info("Peer ended conversation.")
                break

            print(f"Peer: {text}")

        peer_socket.close()
        conn.close()

    def chat_loop_receiver(self, peer_socket: socket, conn: socket):
        """
        Encrypted chat for the client who received the key exchange
        Type 'stop' to send 'goodbye' and end
        """
        if self.block_cipher is None:
            logger.error("BlockCipher not initialized.")
            return

        logger.info("Starting encrypted chat (peer sends first).")

        to_pad = True
        running = True
        while running:
            response = recv_transfer_dto(conn)
            if response is None:
                logger.info("Peer closed connection.")
                break
            if response.action != ActionMode.CHAT_MESSAGE:
                logger.error(f"Unexpected action: {response.action}")
                break

            try:
                decrypted = self.block_cipher.decrypt(response.data, remove_padding=True)
                if to_pad:
                    decrypted = self.block_cipher.depad(decrypted)
                    to_pad = False
                text = decrypted.decode(errors="replace")
            except Exception as e:
                logger.exception(f"Decryption error: {e}")
                break

            if text.strip().lower() == "goodbye":
                logger.info("Peer ended conversation.")
                break

            print(f"Peer: {text}")

            msg = input("You: ")
            if msg.strip().lower() == "stop":
                plaintext = b"goodbye"
            else:
                plaintext = msg.encode()

            encrypted = self.block_cipher.encrypt(plaintext)
            dto = TransferDTO(action=ActionMode.CHAT_MESSAGE, data=encrypted)
            send_transfer_dto(dto, peer_socket)

            if msg.strip().lower() == "stop":
                logger.info("Sent goodbye. Ending chat.")
                break

        peer_socket.close()
        conn.close()


def print_help():
    print("=" * 40)
    print("Available commands:")
    print("1 - Generate and register RSA key pair")
    print("2 - Request public key from server")
    print("3 - Initialize a conversation with another client")
    print("4 - Wait for a peer-to-peer conversation request from another peer")
    print("5 - Start listener")
    print("6 - Stop listener")
    print("7 - Exit")


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
        command = input("Enter command (help for list of commands)\n")
        match command:
            case "1":
                # Register key pair
                client.generate_and_register_key()
            case "2":
                # Request a public key
                requested_id = input("Enter user ID to request public key for: ")
                client.request_public_key(int(requested_id))
            case "3":
                # Start chatting with another client as client 1
                peer_id = input("Enter peer ID to chat with: ")
                try:
                    client_id = int(client_id)
                except ValueError:
                    print("Peer ID must be an integer")
                    continue
                client.handle_first_peer_communication(int(peer_id))
            case "4":
                # Wait for a chatting opportunity as client 2
                client.handle_second_peer_communication()
            case "5":
                # Start listener
                client.run_listener()
            case "6":
                # Stop listener
                client.stop_listener()
            case "7":
                to_loop = False
                print("Goodbye!")
            case _:
                print_help()


if __name__ == "__main__":
    run_communication()
