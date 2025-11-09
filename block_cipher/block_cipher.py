import json
from typing import Callable
from enum import Enum

class CipherMode(str, Enum):
    ECB = "ECB"
    CBC = "CBC"
    CFB = "CFB"
    OFB = "OFB"
    CTR = "CTR"

class PaddingMode(str, Enum):
    ZERO = "zero"
    DES = "des"
    SF = "sf"

# Helper function
def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Cannot XOR non-equal length byte sequences")
    return bytes(x ^ y for x, y in zip(a, b))

class BlockCipher:
    block_length : int
    mode : CipherMode
    encrypting_algorithm : Callable
    decryption_algorithm : Callable
    key : str
    iv : bytes | None
    padding_mode : PaddingMode

    def __init__(self, block_length : int, key : str, iv : str | None, mode : CipherMode, padding_mode : PaddingMode, encrypting_algorithm : Callable, decryption_algorithm : Callable):
        """
        Initializes a Block Cipher

        :param block_length: Length of the encryption block
        :param key: Encryption key
        :param iv: Initialization vector
        :param mode: Encryption mode (CBC, ECB, CFB, OFB, CTR)
        :param padding_mode: Padding mode (ZERO, DES, SF)
        """
        if block_length % 8 != 0:
            raise ValueError("Block length must be a multiple of 8")
        block_length = block_length // 8

        self.block_length = block_length
        self.key = key
        self.mode = mode
        self.iv = iv
        self.padding_mode = padding_mode
        self.encrypting_algorithm = encrypting_algorithm
        self.decryption_algorithm = decryption_algorithm
        self.applied_padding = False

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value: CipherMode):
        if not isinstance(value, CipherMode):
            raise ValueError("Mode must be a CipherMode enum")
        self._mode = value

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, value: str | bytes | None):
        if value is None:
            value = b"0" * self.block_length
        elif isinstance(value, str):
            value = value.encode()
        elif not isinstance(value, bytes):
            raise ValueError("IV must be bytes, str, or None")

        if self.mode != CipherMode.CTR and len(value) != self.block_length:
            raise ValueError(f"IV length must match block length ({self.block_length} bytes)")

        self._iv = value

    @classmethod
    def from_config(cls, file_path: str, encrypting_algorithm : Callable, decryption_algorithm : Callable):
        with open(file_path, "r") as f:
            config = json.load(f)
        block_length = config["block_length"]
        key = config["key"]
        iv = config["iv"]
        mode = CipherMode(config["mode"])
        padding_mode = PaddingMode(config["padding"])
        return cls(block_length, key, iv, mode, padding_mode, encrypting_algorithm, decryption_algorithm)

    def __pad_len(self, data: bytes) -> int:
        """
        Returns the length of padding needed to pad data to the block size
        """
        block_size = self.block_length
        pad_len = block_size - (len(data) % block_size)
        return pad_len

    def pad(self, data: bytes) -> bytes:
        """
        Pads data based on block length and padding mode
        """
        pad_len = self.__pad_len(data)

        match self.padding_mode:
            case PaddingMode.ZERO:
                # Zero padding
                return data + b"\x00" * pad_len
            case PaddingMode.DES:
                # DES padding 1 bit followed by zeroes
                # 0x80 -> 1000,0000
                return data + b"\x80" + b"\x00" * (pad_len - 1)
            case PaddingMode.SF:
                # Schneier-Ferguson padding 'n' * n
                return data + bytes([pad_len]) * pad_len
            case _:
                raise ValueError("Invalid padding mode")

    def depad(self, data: bytes) -> bytes:
        """
        Removes padding from data based on padding mode.
        """
        if not data:
            raise ValueError("Cannot remove padding from empty data")

        match self.padding_mode:
            case PaddingMode.ZERO:
                return data.rstrip(b"\x00")

            case PaddingMode.DES:
                i = len(data) - 1
                while i >= 0 and data[i] == 0x00:
                    i -= 1
                if i < 0 or data[i] != 0x80:
                    raise ValueError("Invalid DES padding")

                return data[:i]

            case PaddingMode.SF:
                pad_len = data[-1]
                if pad_len == 0 or pad_len > len(data):
                    raise ValueError("Invalid SF padding: incorrect pad length.")
                return data[:-pad_len]
            case _:
                raise ValueError("Invalid padding mode")

    def __ecb_encrypt(self, data: bytes):
        """
        Block encryption based on Electronic codebook mode
        """
        # Parallel
        block_size = self.block_length
        encrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            encrypted_block = self.encrypting_algorithm(block, self.key)
            encrypted_data.extend(encrypted_block)
        return encrypted_data

    def __ecb_decrypt(self, data: bytes):
        """
        Block decryption based on Electronic codebook mode
        """
        # Parallel
        block_size = self.block_length
        decrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            encrypted_block = self.decryption_algorithm(block, self.key)
            decrypted_data.extend(encrypted_block)
        return decrypted_data

    def __cbc_encrypt(self, data: bytes):
        """
        Block encryption based on Cipher-block chaining mode
        """
        block_size = self.block_length
        encrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            block = xor(block, c_0)
            encrypted_block = self.encrypting_algorithm(block, self.key)
            encrypted_data.extend(encrypted_block)
            c_0 = encrypted_block
        return encrypted_data

    def __cbc_decrypt(self, data: bytes):
        """
        Block decryption based on Cipher-block chaining mode
        """
        # Parallel
        block_size = self.block_length
        decrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            decrypted_block = self.decryption_algorithm(block, self.key)
            decrypted_block = xor(decrypted_block, c_0)
            decrypted_data.extend(decrypted_block)
            c_0 = block
        return decrypted_data

    def __cfb_encrypt(self, data: bytes):
        """
        Block encryption based on Cipher feedback mode
        """
        block_size = self.block_length
        encrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            c_0 = self.encrypting_algorithm(c_0, self.key)
            c_0 = xor(c_0, block)
            encrypted_data.extend(c_0)
        return encrypted_data

    def __cfb_decrypt(self, data: bytes):
        """
        Block decryption based on Cipher feedback mode
        """
        # Parallel
        block_size = self.block_length
        decrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            c_0 = self.encrypting_algorithm(c_0, self.key)
            decrypted_block = xor(c_0, block)
            decrypted_data.extend(decrypted_block)
            c_0 = block
        return decrypted_data

    def __ofb_encrypt(self, data: bytes):
        """
        Block encryption based on Output feedback mode
        """
        # Parallel
        block_size = self.block_length
        encrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            c_0 = self.encrypting_algorithm(c_0, self.key)
            block = xor(block, c_0)
            encrypted_data.extend(block)
        return encrypted_data

    def __ofb_decrypt(self, data: bytes):
        """
        Block decryption based on Output feedback mode
        """
        # Parallel
        block_size = self.block_length
        decrypted_data = bytearray()
        c_0 = self.iv
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            c_0 = self.encrypting_algorithm(c_0, self.key)
            block = xor(block, c_0)
            decrypted_data.extend(block)
        return decrypted_data

    def __build_ctr_block(self, counter: int) -> bytes:
        """
        Builds a single CTR mode counter-block based on the counter
        """
        iv = self.iv
        block_size = self.block_length
        n_size = len(iv)
        counter_size = block_size - n_size

        if counter_size <= 0:
            raise ValueError("IV is too long for the block size")
        try:
            counter_bytes = counter.to_bytes(counter_size, 'big')
        except OverflowError:
            raise ValueError(f"Counter {counter} is too large for {counter_size} bytes")

        return iv + counter_bytes

    def __ctr_encrypt(self, data: bytes):
        """
        Block encryption based on Counter mode
        """
        # Parallel
        block_size = self.block_length
        encrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            n_i = self.__build_ctr_block(i + 1)
            encrypted_block = self.encrypting_algorithm(n_i, self.key)
            encrypted_block = xor(encrypted_block, block)
            encrypted_data.extend(encrypted_block)
        return encrypted_data

    def __ctr_decrypt(self, data: bytes):
        """
        Block decryption based on Counter mode
        """
        # Parallel
        block_size = self.block_length
        decrypted_data = bytearray()
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            n_i = self.__build_ctr_block(i + 1)
            decrypted_block = self.encrypting_algorithm(n_i, self.key)
            decrypted_block = xor(decrypted_block, block)
            decrypted_data.extend(decrypted_block)
        return decrypted_data

    def encrypt(self, data: bytes):
        """
        Block encryption based on the configuration
        """
        # print("--- RAW DATA (last 32 bytes) ---")
        # print(data[-2*self.block_length:].hex())
        # print("---------------------------------------")
        # print(len(data))

        if len(data) % self.block_length != 0 :
            data = self.pad(data)
            self.applied_padding = True

        match self.mode:
            case CipherMode.ECB:
                return self.__ecb_encrypt(data)
            case CipherMode.CBC:
                return self.__cbc_encrypt(data)
            case CipherMode.CFB:
                return self.__cfb_encrypt(data)
            case CipherMode.OFB:
                return self.__ofb_encrypt(data)
            case CipherMode.CTR:
                return self.__ctr_encrypt(data)
            case _:
                raise ValueError("Invalid mode")


    def decrypt(self, data: bytes, remove_padding : bool = True) -> bytes:
        """
        Block decryption based on the configuration
        """
        decrypted_data = bytearray()

        match self.mode:
            case CipherMode.ECB:
                decrypted_data = self.__ecb_decrypt(data)
            case CipherMode.CBC:
                decrypted_data = self.__cbc_decrypt(data)
            case CipherMode.CFB:
                decrypted_data = self.__cfb_decrypt(data)
            case CipherMode.OFB:
                decrypted_data = self.__ofb_decrypt(data)
            case CipherMode.CTR:
                decrypted_data = self.__ctr_decrypt(data)
            case _:
                raise ValueError("Invalid mode")

        # Convert the final result to bytes from bytearray
        if remove_padding and self.applied_padding:
            return bytes(self.depad(decrypted_data))
        else:
            return bytes(decrypted_data)

