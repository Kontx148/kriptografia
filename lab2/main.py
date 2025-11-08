from block_cipher.block_cipher import *
from lab1.crypto import *

if __name__ == "__main__":
    #block_cipher2 = BlockCipher(2,2,2,2,PaddingMode.ZERO)
    block_cipher = BlockCipher.from_config("block_cipher/config.json")
    print(block_cipher)