from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES


def get_random_string(length: int) -> bytes:
    while True:
        return_string = b""
        for x in range(0, length):
            return_string += get_random_bytes(1)
        if b"\x00" not in return_string:
            break
    return return_string


def encrypt_with_padding(key: bytes, plaintext: bytes) -> tuple[bool, bytes]:
    length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0, 14)
    plaintext_padded = plaintext + get_random_string(length-1) + bytes([length])
    if len(key) != 16 and len(key) != 32 and len(key) != 24:
        return False, b""
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(plaintext_padded)
    return True, ciphertext


def decrypt_with_padding(key: bytes, cipher_text:  bytes) -> tuple[bool, bytes]:
    if len(key) != 16 and len(key) != 32 and len(key) != 24:
        return False, b""
    plaintext_padded = AES.new(key, AES.MODE_ECB).decrypt(cipher_text)
    plaintext = plaintext_padded[:-plaintext_padded[-1]]
    return True, plaintext
