import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import BaseModel


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def encrypt_challenge(key: bytes, challenge: str) -> Challenge:
    """Encrypts challenge in CBC mode using the provided key."""
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(challenge.encode())
    padded_data += padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data)
    ciphertext += encryptor.finalize()

    encoded_iv = b64encode(iv)
    encoded_ciphertext = b64encode(ciphertext)
    return Challenge(iv=encoded_iv, ciphertext=encoded_ciphertext)


def decrypt_challenge(key: bytes, challenge: Challenge) -> str:
    """Decrypts encrypted challenge; reveals a password that can be
    used to unlock the next task/challenge.
    """
    iv = b64decode(challenge.iv)
    ciphertext = b64decode(challenge.ciphertext)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode()


if __name__ == '__main__':
    plaintext = "Hello world"
    key = os.urandom(16)

    result = encrypt_challenge(key=key, challenge=plaintext)
    print(result)

    decripted_result = decrypt_challenge(key=key, challenge=result)
    print(f"Decrypted reszult: {decripted_result}")
