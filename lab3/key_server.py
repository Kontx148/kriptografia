from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from common import DEFAULT_PORT

from socket import *
from threading import Thread
import logging

from lab3.common import encode_public_key, decode_public_key
from lab3.comm_utils import TransferDTO, ActionMode, ResponseDTO, recv_transfer_dto, send_response_dto

serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', DEFAULT_PORT))
serverSocket.listen(1)

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()
logger.info('The server is ready to receive')

public_keys: dict[int, RSAPublicKey] = {}


def register_public_key(dto: TransferDTO, cs: socket):
    try:
        user_id_data, pem_key = dto.data.split(b'\n', 1)
        user_id = int.from_bytes(user_id_data, 'big')
        user_public_key = decode_public_key(pem_key)
        public_keys[user_id] = user_public_key
        logger.info(f"Public key registered: user {user_id}")
        response_dto = ResponseDTO(True, b'OK')
    except Exception as e:
        logger.error(f'Error registering public key: {e}')
        response_dto = ResponseDTO(False, b'Error registering public key')
    send_response_dto(response_dto, cs)


def request_public_key(dto: TransferDTO, cs: socket):
    user_id = int.from_bytes(dto.data, 'big')
    logger.info(f"Requesting public key for user {user_id}")
    public_key = public_keys.get(user_id)
    if public_key:
        response_dto = ResponseDTO(True, encode_public_key(public_key))
    else:
        response_dto = ResponseDTO(False, b'Could not find public key for user_id ' + str(user_id).encode())
    send_response_dto(response_dto, cs)

def client_handler(cs: socket):
    #cs.settimeout(5)
    logger.info('Serving client...')
    toLoop = True
    while toLoop:
        dto = recv_transfer_dto(cs)

        if not dto:
            logger.warning('Connection interrupted')
            break

        logger.info('Received action: ' + dto.action.name + ' ' + 'from client' + str(cs.getpeername()))
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

