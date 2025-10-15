#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import math
from typing import List, Tuple

from lab1.utils import shift_right, shift_left


# Caesar Cipher

def encrypt_caesar(plaintext : str):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    ciphertext = ''
    for ch in plaintext:
        if ch.isalpha():
            ch = ch.upper()
            ciphertext += shift_right(ch, 3)
        else:
            ciphertext += ch
    return ciphertext


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    plaintext = ''
    for ch in ciphertext:
        if ch.isalpha():
            ch = ch.upper()
            plaintext += shift_left(ch, 3)
        else:
            plaintext += ch
    return plaintext


# Vigenere Cipher

def encrypt_vigenere(plaintext : str, keyword : str):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    keyword = keyword.upper()
    ciphertext = ''
    for i, ch in enumerate(plaintext):
        if ch.isalpha():
            ch = ch.upper()
            shift_value = ord(keyword[i % len(keyword)]) - ord('A')
            ciphertext += shift_right(ch, shift_value)
        else:
            ciphertext += ch
    return ciphertext


def decrypt_vigenere(ciphertext : str, keyword : str):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    plaintext = ''
    for i, ch in enumerate(ciphertext):
        if ch.isalpha():
            ch = ch.upper()
            shift_value = ord(keyword[i % len(keyword)]) - ord('A')
            plaintext += shift_left(ch, shift_value)
        else:
            plaintext += ch
    return plaintext


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

# Scytale Cipher
def encrypt_scytale(plaintext : str, circumference : int):
    """
    Encrypt plaintext using a Scytale cipher with a circumference.
    """
    ciphertext = ''
    for i in range(circumference):
        for j in range(i, len(plaintext), circumference):
            ciphertext += plaintext[j]
    return ciphertext


def decrypt_scytale(ciphertext : str, circumference : int):
    """
    Decrypt ciphertext using a Scytale cipher with a circumference.
    """
    plaintext = ''
    # Get the base length i.e., each rows length
    base = math.ceil(len(ciphertext) / circumference)
    extra = len(ciphertext) % circumference

    # Get the shift list -> by how much do we need to shift each row to get to the next
    shift_list = [0]
    for i in range(1, circumference):
        if i > extra and extra:
            shift_list.append(shift_list[i - 1] + base - 1)
        else:
            shift_list.append(shift_list[i - 1] + base)

    # Loop through each column
    for i in range(base):
        # In the last column, we only need to extra number of characters
        if i == base - 1 and extra:
            shift_list = shift_list[:extra]

        for shift in shift_list:
            if shift + i >= len(ciphertext):
                continue
            plaintext += ciphertext[shift + i]
    return plaintext

# Rail fence Cipher

def get_gaps(rails : int) -> Tuple[int, List[Tuple[int, int]]]:
    gap_length = 2 * (rails - 1)
    gap_list = [(i, gap_length - i) for i in range(gap_length, -1, -2)]
    gap_list[0] = (gap_length, gap_length)
    gap_list[-1] = (gap_length, gap_length)
    return gap_length, gap_list

def extra_on_rail(given_rail : int, rails : int, extra : int) -> int:
    """
    Returns the extra number of characters on the given rail, given outside the fixed periods

    :param given_rail: The rail number between 0 and rails - 1
    :param rails: The number of rails
    :param extra: The extra number of characters
    """
    match given_rail:
        # Upper
        case 0:
            return 1 if extra else 0
        # Lower
        case _ if given_rail == rails - 1:
            return 1 if extra >= rails else 0
        # Left and right
        case _:
            if extra > given_rail:
                if extra + given_rail >= 2 * rails - 1:
                    return 2
                else:
                    return 1
            else:
                return 0


def encrypt_rail_fence(plaintext : str, rails : int):
    """
    Encrypt plaintext using a Rail fence cipher with a rail size.
    """
    ciphertext = ''
    gap_length, gap_list = get_gaps(rails)

    for i in range(rails):
        gap = gap_list[i]
        current_index = i
        gap_index = 0
        while current_index < len(plaintext):
            ciphertext += plaintext[current_index]
            current_index += gap[gap_index]
            gap_index = (gap_index + 1) % 2

    return ciphertext

def decrypt_rail_fence(ciphertext : str, rails : int):
    """
    Decrypt ciphertext using a Rail fence cipher with a rail size.
    """
    plaintext = ''
    period_length = 2 * (rails - 1)
    base = len(ciphertext) // period_length
    extra = len(ciphertext) % period_length

    # Period indexes
    # 0
    #  left        right
    #        lower

    upper = 0
    lower = 0
    left = []
    right = []

    # Fill the left and right indexes
    for i in range(1, rails):
        if i == 1:
            shift_value = base + extra_on_rail(0, rails, extra)
        else:
            extra_shift = extra_on_rail(i - 1, rails, extra)
            shift_value = 2 * base + left[-1] + extra_shift

        # Compute the lower index
        if i == rails - 1:
            lower = shift_value
        # Compute the left and right
        else:
            left.append(shift_value)
            right.append(shift_value + 1)

    # Fill in the fixed periods
    for i in range(base):
        plaintext += ciphertext[upper + i]

        # Loop through the left side
        for left_index in left:
            plaintext += ciphertext[left_index + 2 * i]

        # Add the lower
        plaintext += ciphertext[lower + i]

        # Loop through the right side
        for right_index in right:
            plaintext += ciphertext[right_index + 2 * i]

    # Fill in the extra characters
    for i in range(extra):
        match i:
            case 0:
                plaintext += ciphertext[upper + base]
            case _ if i == rails - 1:
                plaintext += ciphertext[lower + base]
            case _ if i < rails - 1:
                plaintext += ciphertext[left[-1] + 2 * base]
            case _:
                plaintext += ciphertext[right[-1] + 2 * base]

    return plaintext






