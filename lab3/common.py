from enum import Enum
import pickle
from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

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


class ActionMode(Enum):
    REGISTER_PUBLIC_KEY = 1
    REQUEST_PUBLIC_KEY = 2
    CLOSE_CONNECTION = 3


class ServerResponseDTO:
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
    def from_bytes(raw: bytes) -> 'ServerResponseDTO':
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

        return ServerResponseDTO(success=success, data=bytes(data))

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
