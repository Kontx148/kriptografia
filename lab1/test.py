import unittest

from lab1.crypto import *


class EncryptUnitTests(unittest.TestCase):
    # Ceaser Cipher
    def test_caesar(self, plaintext : str = "CAESAR") :
        ciphertext = encrypt_caesar(plaintext)
        deciphered = decrypt_caesar(ciphertext)
        self.assertEqual(plaintext, deciphered)

        ciphertext_test_1 = encrypt_caesar("PYTHON")
        self.assertEqual(ciphertext_test_1, "SBWKRQ")

        ciphertext_test_2 = decrypt_caesar("SBWKRQ")
        self.assertEqual(ciphertext_test_2, "PYTHON")

        ciphertext_test_3 = encrypt_caesar("PYTHON", 10)
        deciphered_test_3 = decrypt_caesar(ciphertext_test_3, 10)
        self.assertEqual(deciphered_test_3, "PYTHON")

        combined_text = "abc123,.,,,,..2323"
        ciphertext_test_4 = encrypt_caesar(combined_text)
        deciphered_test_4 = decrypt_caesar(ciphertext_test_4)
        self.assertEqual(combined_text.upper(), deciphered_test_4)

    # Vigenere Cipher
    def test_vigenere(self, plaintext : str = "VIGENERE", keyword : str = "KEY"):
        ciphertext = encrypt_vigenere(plaintext, keyword)
        deciphered = decrypt_vigenere(ciphertext, keyword)
        self.assertEqual(plaintext, deciphered)

        ciphertext_test_1 = encrypt_vigenere("ATTACKATDAWN", "LEMON")
        self.assertEqual(ciphertext_test_1, "LXFOPVEFRNHR")

        ciphertext_test_2 = decrypt_vigenere("LXFOPVEFRNHR", "LEMON")
        self.assertEqual(ciphertext_test_2, "ATTACKATDAWN")

        combined_text = "abc123,.,,,,..2323"
        ciphertext_test_4 = encrypt_vigenere(combined_text, keyword)
        deciphered_test_4 = decrypt_vigenere(ciphertext_test_4, keyword)
        self.assertEqual(combined_text.upper(), deciphered_test_4)


    # Scytale Cipher
    def test_scytale(self, plaintext : str = "ASDFGH", circumference : int = 5):
        ciphertext = encrypt_scytale(plaintext, circumference)
        deciphered = decrypt_scytale(ciphertext, circumference)
        self.assertEqual(plaintext.upper(), deciphered)

        # Scytale with an incomplete period
        plaintext_test_1 = "HELLOWORLD"
        circumference_test_1 = 4
        ciphertext_test_1 = encrypt_scytale(plaintext_test_1, circumference_test_1)
        deciphered_test_1 = decrypt_scytale(ciphertext_test_1, circumference_test_1)
        self.assertEqual(plaintext_test_1, deciphered_test_1)

        # With a single, long period
        plaintext_test_2  = "HELLOWORLD"
        circumference_test_2 = 20
        ciphertext_test_2 = encrypt_scytale(plaintext_test_2, circumference_test_2)
        deciphered_test_2 = decrypt_scytale(ciphertext_test_2, circumference_test_2)
        self.assertEqual(plaintext_test_2, deciphered_test_2)

        # With a period of 1
        plaintext_test_3  = "HELLOWORLD"
        circumference_test_3 = 1
        ciphertext_test_3 = encrypt_scytale(plaintext_test_3, circumference_test_3)
        deciphered_test_3 = decrypt_scytale(ciphertext_test_3, circumference_test_3)
        self.assertEqual(plaintext_test_3, deciphered_test_3)


    # Railfence Cipher
    def test_rail_fence(self, plaintext : str = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG", rails : int = 3):
        ciphertext = encrypt_rail_fence(plaintext, rails)
        deciphered = decrypt_rail_fence(ciphertext, rails)
        self.assertEqual(plaintext.upper(), deciphered)

        # Railfence with an incomplete period
        plaintext_test_1 = "AEZAKMINEVERWANTEDGTA"
        rails_test_1 = 6
        ciphertext_test_1 = encrypt_rail_fence(plaintext_test_1, rails_test_1)
        deciphered_test_1 = decrypt_rail_fence(ciphertext_test_1, rails_test_1)
        self.assertEqual(plaintext_test_1, deciphered_test_1)

        # Railfence with a single, long period
        plaintext_test_2  = "AEZAKMI"
        rails_test_2 = 20
        ciphertext_test_2 = encrypt_rail_fence(plaintext_test_2, rails_test_2)
        deciphered_test_2 = decrypt_rail_fence(ciphertext_test_2, rails_test_2)
        self.assertEqual(plaintext_test_2, deciphered_test_2)

        # Railfence with a period of 1
        plaintext_test_3  = "HELLOWORLD"
        rails_test_3 = 1
        ciphertext_test_3 = encrypt_rail_fence(plaintext_test_3, rails_test_3)
        deciphered_test_3 = decrypt_rail_fence(ciphertext_test_3, rails_test_3)
        self.assertEqual(plaintext_test_3, deciphered_test_3)

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
    #unittest.main(verbosity=2)
    test_intelligent_codebreaker()