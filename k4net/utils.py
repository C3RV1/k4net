def encrypt_with_padding(key: 'AES Object', plaintext: bytes) -> bytes:
    length = (16 - (len(plaintext) % 16))
    plaintext_padded = plaintext + bytes([length]) * length
    ciphertext = key.encrypt(plaintext_padded)
    return ciphertext


def decrypt_with_padding(key: 'AES Object', cipher_text:  bytes) -> bytes:
    plaintext_padded = key.decrypt(cipher_text)
    plaintext = plaintext_padded[:-plaintext_padded[-1]]
    return plaintext
