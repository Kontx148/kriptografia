import pickle
from socket import socket
from typing import Any

from block_cipher.block_cipher import *

from Crypto.Cipher import AES

IV = b'\x9f\x3a\x7c\x12\xe4\x56\xab\x90\xcd\x21\x88\xfe\x47\x6b\x11\xde'

def encrypt_aes_bytes(data: bytes, key: str, mode=AES.MODE_CBC) -> bytes:
    key = key.encode()
    cipher = AES.new(key, mode, iv=IV)
    return cipher.encrypt(data)

def decrypt_aes_bytes(data: bytes, key: str, mode=AES.MODE_CBC) -> bytes:
    key = key.encode()
    cipher = AES.new(key, mode, iv=IV)
    return cipher.decrypt(data)

# Block Cipher config file path

BLOCK_CIPHER_CONFIG_PATH = "block_cipher/config.json"

# Action Enum

class ActionMode(Enum):
    REGISTER_PUBLIC_KEY = 1
    REQUEST_PUBLIC_KEY = 2
    CLOSE_CONNECTION = 3
    REQUEST_PEER_TO_PEER_COMMUNICATION = 4
    SENDING_BLOCK_CIPHER = 5
    SENDING_HALF_SECRET = 6
    REQUEST_HALF_SECRET = 7
    SEND_ENCRYPTED_MESSAGE = 8

# Dto's

class ResponseDTO:
    def __init__(self, success: bool, data: bytes):
        self.success = success
        self.data = data

    def to_bytes(self) -> bytes:
        payload = {
            'success': self.success,
            'data': self.data,
        }
        return pickle.dumps(payload)

    @staticmethod
    def from_bytes(raw: bytes) -> 'ResponseDTO':
        try:
            payload: Any = pickle.loads(raw)
        except Exception as e:
            raise ValueError(f'Invalid response bytes: {e}')

        if not isinstance(payload, dict):
            raise ValueError('Response payload is not a dict')

        if 'success' not in payload or 'data' not in payload:
            raise ValueError('Response missing required fields')

        success = payload['success']
        data = payload['data']

        if not isinstance(success, bool):
            raise ValueError('Response success must be bool')
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('Response data must be bytes')

        return ResponseDTO(success=success, data=bytes(data))

class TransferDTO:
    def __init__(self, action: ActionMode, data: bytes):
        self.action = action
        self.data = data

    def to_bytes(self) -> bytes:
        payload = {
            'action': self.action.value,
            'data': self.data,
        }
        return pickle.dumps(payload)

    @staticmethod
    def from_bytes(raw: bytes) -> 'TransferDTO':
        """
        Deserialize DTO from bytes, raising ValueError if invalid"""
        try:
            payload: Any = pickle.loads(raw)
        except Exception as e:
            raise ValueError(f'Invalid DTO bytes: {e}')

        if not isinstance(payload, dict):
            raise ValueError('DTO payload is not a dict')

        if 'action' not in payload or 'data' not in payload:
            raise ValueError('DTO missing required fields')

        try:
            action = ActionMode(payload['action'])
        except ValueError:
            raise ValueError('Unknown action mode')

        data = payload['data']
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('DTO data must be bytes')

        return TransferDTO(action=action, data=bytes(data))

# Misc
def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def recv_response_dto(sock) -> ResponseDTO | None:
    # read 4-byte length
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    # read actual payload
    msg = recv_exact(sock, msg_len)
    if msg is None:
        return None
    return ResponseDTO.from_bytes(msg)

def recv_transfer_dto(sock) -> TransferDTO | None:
    # read 4-byte length
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = int.from_bytes(raw_len, 'big')
    # read actual payload
    msg = recv_exact(sock, msg_len)
    if msg is None:
        return None
    return TransferDTO.from_bytes(msg)

def send_transfer_dto(dto: TransferDTO, socket_to_send : socket):
    payload = dto.to_bytes()
    length = len(payload).to_bytes(4, 'big')
    socket_to_send.sendall(length + payload)

def send_response_dto(dto: ResponseDTO, socket_to_send : socket):
    payload = dto.to_bytes()
    length = len(payload).to_bytes(4, 'big')
    socket_to_send.sendall(length + payload)


