from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization

from common import DEFAULT_PORT

from socket import *
from threading import Thread
import logging

from lab3.common import TransferDTO, ActionMode, encode_public_key, decode_public_key, ServerResponseDTO

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', DEFAULT_PORT))
serverSocket.listen(1)

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()

logger.info('The server is ready to receive')

public_keys: dict[int, RSAPublicKey] = {}

def receive_all_bytes(sock):
    BUFF_SIZE = 4096
    data = b''
    try:
        while True:
            part = sock.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
    except timeout:
        return b'Connection: timeout'
    return data

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def recv_dto(sock):
    # read 4-byte length
    raw_len = recv_exact(sock, 4)
    msg_len = int.from_bytes(raw_len, 'big')
    # read actual payload
    msg = recv_exact(sock, msg_len)
    return msg

def register_public_key(dto: TransferDTO, cs: socket):
    try:
        raw = dto.data
        user_id_data, pem_key = raw.split(b'\n', 1)
        user_id = int(user_id_data.decode())
        user_public_key = decode_public_key(pem_key)
        public_keys[user_id] = user_public_key
        logger.info(f"Public key registered: user {user_id}")
        response_dto = ServerResponseDTO(True, b'OK')
    except Exception as e:
        logger.error(f'Error registering public key: {e}')
        response_dto = ServerResponseDTO(False, b'Error registering public key')
    cs.sendall(response_dto.to_bytes())

def request_public_key(dto: TransferDTO, cs: socket):
    user_id = int.from_bytes(dto.data, 'big')
    public_key = public_keys.get(user_id)
    if public_key:
        response_dto = ServerResponseDTO(True, encode_public_key(public_key))
    else:
        response_dto = ServerResponseDTO(False, b'Could not find public key for user_id ' + str(user_id).encode())
    cs.sendall(response_dto.to_bytes())

def client_handler(cs: socket):
    #cs.settimeout(5)
    logger.info('Serving client...')
    toLoop = True
    while toLoop:
        request = recv_dto(cs)

        if not request:
            logger.warning('Connection interrupted')
            break

        try:
            dto = TransferDTO.from_bytes(request)
        except ValueError as e:
            logger.error(f'DTO parse error: {e}')
            break

        match dto.action:
            case ActionMode.REGISTER_PUBLIC_KEY:
                register_public_key(dto, cs)
            case ActionMode.REQUEST_PUBLIC_KEY:
                request_public_key(dto, cs)
            case ActionMode.CLOSE_CONNECTION:
                toLoop = False

        if not toLoop:
            break

    cs.close()
    logger.info('Connection closed')

if __name__ == '__main__':
    while True:
        connectionSocket, addr = serverSocket.accept()
        thread = Thread(target=client_handler, args=(connectionSocket,))
        thread.start()

