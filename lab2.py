import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import StringConstraints, BaseModel


from typing_extensions import Annotated
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

def derive_key(key_seed: str, key_length=32) -> bytes:
    """Derives encryption/decryption key from the given key_seed.
    Uses modern key derivation function (KDF) scrypt.
    """
    kdf = Scrypt(
        salt=b"",
        length=key_length,
        n=2**14,
        r=8,
        p=1,
    )
    key = kdf.derive(key_seed.encode())
    return key


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
    cookie = "tsmatheloftuisof"
   
    key = derive_key(key_seed=cookie)

    challange = Challenge(iv="tBmUXkBI6r8Xq2wJQPWEwg==", ciphertext="eHPQDm2w68FCMqpMN6mEpFjvvrks6Rfm0OlqNU5xBf1LIgcfqIGLqbRDCJbmDcXfhmwZvYiMYigykUX6+3oUS52H/YJCkdRR4PNK3VTe7LAPSBDlEuW5IDCHpjkXD7qF")
    recovered_plaintext = decrypt_challenge(key=key, challenge=challange)
    print(f"Decripted challange: {recovered_plaintext}")