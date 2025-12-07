from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from common import DEFAULT_PORT

from socket import *
from threading import Thread
import logging

from lab3.common import TransferDTO, ActionMode

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

def register_public_key(dto: TransferDTO, cs: socket):
    raw = dto.data.decode()

    user_id_str, pem_key = raw.split('\n', 1)
    user_id = int(user_id_str)

    user_public_key = load_pem_public_key(pem_key.encode())

    public_keys[user_id] = user_public_key

    logger.info(f"Public key registered: user {user_id}")
    cs.sendall(b'OK')

def client_handler(cs: socket):
    cs.settimeout(5)
    logger.info('Serving client...')
    toLoop = True
    while toLoop:
        request = receive_all_bytes(cs)

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

        if not toLoop:
            break

    cs.close()
    logger.info('Connection closed')

if __name__ == '__main__':
    while True:
        connectionSocket, addr = serverSocket.accept()
        thread = Thread(target=client_handler, args=(connectionSocket,))
        thread.start()

