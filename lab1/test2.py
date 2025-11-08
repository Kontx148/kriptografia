from lab1.crypto import *

# Intelligent codebreaker
def test_intelligent_codebreaker():
    plaintext = "The quick, brown fox jumps over the lazy dog"
    key = "poignant"
    ciphertext = encrypt_vigenere(plaintext, key)
    print(ciphertext)
    deciphered = intelligent_codebreaker(ciphertext)
    print(deciphered)
    if deciphered:
        print(deciphered)
    else:
        print("No key found")

if __name__ == '__main__':
    test_intelligent_codebreaker()