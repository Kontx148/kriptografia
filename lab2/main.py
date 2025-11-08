from block_cipher.block_cipher import *
from lab1.crypto import *

if __name__ == "__main__":
    block_cipher = BlockCipher.construct_from_config("block_cipher/config.json")
    print(block_cipher)