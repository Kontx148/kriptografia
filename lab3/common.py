from enum import Enum
import pickle
from typing import Any


DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 12000


class ActionMode(Enum):
    REGISTER_PUBLIC_KEY = 1


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
