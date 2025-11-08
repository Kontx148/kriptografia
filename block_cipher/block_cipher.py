import json
from typing import Callable

class BlockCipher:
    block_length : int
    mode : str
    encrypting_algorithm : Callable
    decryption_algorithm : Callable
    key : str
    iv : str
    padding_mode : str

    def __init__(self, block_length : int, key : str, iv : str, mode : str, padding_mode : str):
        """
        :param block_length: Block length (multiple of 8)
        """
        self.block_length = block_length
        self.key = key
        self.iv = iv
        self.mode = mode
        self.padding_mode = padding_mode

    @classmethod
    def from_config(cls, file_path: str):
        with open(file_path, "r") as f:
            config = json.load(f)
        block_length = config["block_length"]
        key = config["key"]
        iv = config["iv"]
        mode = config["mode"]
        padding_mode = config["padding"]
        return cls(block_length, key, iv, mode, padding_mode)

    def pad(self, data: bytes) -> bytes:
        """
        Pads data based on block length and padding mode
        """
        block_size = self.block_length
        # Compute padding length
        pad_len = block_size - (len(data) % block_size)

        # Apply padding based on padding mode
        # Zero padding
        if self.padding_mode == "zero":
            return data + b"\x00" * pad_len
        # DES padding 1 bit followed by zeroes
        # 0x80 -> 1000,0000
        elif self.padding_mode == "des":
            return data + b"\x80" + b"\x00" * (pad_len - 1)
        # Schneier-Ferguson padding 'n' * n
        elif self.padding_mode == "sf":
            return data + bytes([pad_len]) * pad_len
        else:
            raise ValueError("Invalid padding mode")


