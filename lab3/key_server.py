from socket import *
from threading import Thread
import logging

class KeyServer:
    def __init__(self):
        self.keys = {}

serverPort = 12000
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(('', serverPort))
serverSocket.listen(1)

logging.basicConfig(format='[%(threadName)s] %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger()

logger.info('The server is ready to receive')


def recvall(sock):
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


def client_handler(cs: socket):
    cs.settimeout(5)
    logger.info('Serving client...')
    toLoop = True
    while toLoop:
        requests = recvall(cs).decode().split('\r\n')

        if not requests:
            logger.warning('Connection interrupted')
            break

        for request in requests:
            if request == 'Connection: close':
                logger.info('Closing connection as per request')
                toLoop = False
                break
            if request == 'Connection: timeout':
                logger.warning('Connection timed out')
                toLoop = False
                break

        if not toLoop:
            break
    cs.close()
    logger.info('Connection closed')


while True:
    connectionSocket, addr = serverSocket.accept()
    thread = Thread(target=client_handler, args=(connectionSocket,))
    thread.start()

