import unittest

from block_cipher.block_cipher import *
from lab1.crypto import *

from Crypto.Cipher import AES

BLOCK_SIZE = 16
IV = b'\x9f\x3a\x7c\x12\xe4\x56\xab\x90\xcd\x21\x88\xfe\x47\x6b\x11\xde'

def encrypt_aes_bytes(data: bytes, key: str, mode=AES.MODE_CBC) -> bytes:
    key = key.encode()
    cipher = AES.new(key, mode, iv=IV)
    return cipher.encrypt(data)

def decrypt_aes_bytes(data: bytes, key: str, mode=AES.MODE_CBC) -> bytes:
    key = key.encode()
    cipher = AES.new(key, mode, iv=IV)
    return cipher.decrypt(data)

class EncryptUnitTests(unittest.TestCase):
    # Hook method for setting up the test fixture before exercising it
    def setUp(self):
        config_file_path = "block_cipher/config.json"
        binary_file_path = "lab2/data_tiny.bin"
        self.block_cipher_vigenere = BlockCipher.from_config(config_file_path, encrypt_vigenere_bytes, decrypt_vigenere_bytes)
        self.block_cipher_aes = BlockCipher.from_config(config_file_path, encrypt_aes_bytes, decrypt_aes_bytes)
        self.binary_file_path = binary_file_path

    def test_ecb(self):
        self.block_cipher_vigenere.mode = CipherMode.ECB
        self.block_cipher_aes.mode = CipherMode.ECB
        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_vigenere.encrypt(data)
            decrypted_data = self.block_cipher_vigenere.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_aes.encrypt(data)
            decrypted_data = self.block_cipher_aes.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)
    def test_cbc(self):
        self.block_cipher_vigenere.mode = CipherMode.CBC
        self.block_cipher_aes.mode = CipherMode.CBC
        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_vigenere.encrypt(data)
            decrypted_data = self.block_cipher_vigenere.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_aes.encrypt(data)
            decrypted_data = self.block_cipher_aes.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)
    def test_cfb(self):
        self.block_cipher_vigenere.mode = CipherMode.CFB
        self.block_cipher_aes.mode = CipherMode.CFB
        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_vigenere.encrypt(data)
            decrypted_data = self.block_cipher_vigenere.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_aes.encrypt(data)
            decrypted_data = self.block_cipher_aes.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)
    def test_ofb(self):
        self.block_cipher_vigenere.mode = CipherMode.OFB
        self.block_cipher_aes.mode = CipherMode.OFB
        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_vigenere.encrypt(data)
            decrypted_data = self.block_cipher_vigenere.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_aes.encrypt(data)
            decrypted_data = self.block_cipher_aes.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)
    def test_ctr(self):
        self.block_cipher_vigenere.mode = CipherMode.CTR
        self.block_cipher_aes.mode = CipherMode.CTR
        self.block_cipher_vigenere.iv = self.block_cipher_aes.iv[12:]
        self.block_cipher_aes.iv = self.block_cipher_aes.iv[12:]
        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_vigenere.encrypt(data)
            decrypted_data = self.block_cipher_vigenere.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

        with open(self.binary_file_path, "rb") as f:
            data = f.read()
            encrypted_data = self.block_cipher_aes.encrypt(data)
            decrypted_data = self.block_cipher_aes.decrypt(encrypted_data)
            self.assertEqual(data, decrypted_data)

if __name__ == '__main__':
    unittest.main(verbosity=2)
