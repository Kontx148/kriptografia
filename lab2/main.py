from block_cipher.block_cipher import *
from lab1.crypto import *

if __name__ == "__main__":
    #block_cipher2 = BlockCipher(2,2,2,2,PaddingMode.ZERO)
    block_cipher = BlockCipher.from_config("block_cipher/config.json", encrypt_vigenere_bytes, decrypt_vigenere_bytes)
    encrypted = block_cipher.encrypt(b"Helloworld")
    print(encrypted)
    print(block_cipher.decrypt(encrypted, remove_padding=True))