import requests
import string
import os
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import StringConstraints, BaseModel


def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password}
    )
    response.raise_for_status()
    return response.json().get("access_token")


def get_challenge(url):
    response = requests.get(
        url,
    )
    response.raise_for_status()
    return response.json()


class Ciphertext(BaseModel):
    ciphertext: str


class Challenge(BaseModel):
    iv: str
    ciphertext: str


def encrypt_chosen_plaintext(plaintext: str, token: str, url: str) -> str:
    response = requests.post(
        url=url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },    
        json={"plaintext": plaintext}
    )

    response.raise_for_status()
    return response.json().get("ciphertext")


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


if __name__ == "__main__":
    username = "hrkac_marijana"
    password = "lstthedtep"
    plaintext = "xxxxxxxxxxxxxxx"
    # token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJocmthY19tYXJpamFuYSIsInNjb3BlIjoiZWNiIiwiZXhwIjoxNzExNTQ4NTY2fQ.pX1RlFP4q_jzfgpQ3xXRe1YfzTQ-a3P1a9JKHIc4x9w"   
    lowercase_alphabet = string.ascii_lowercase

    # Step 1: Get the token
    url_token = "http://10.0.15.2/ecb/token"
    token = get_access_token(username, password, url_token)
    #print(token)

    url = "http://10.0.15.2/ecb"
    cookie = ""
    for i in range(1, 17):
        plaintext = "x"*(16-i)
        chipertext_test = encrypt_chosen_plaintext(plaintext=plaintext, token=token, url=url)
        chipertext_test = chipertext_test[:20]

        for letter in lowercase_alphabet:
            #print(f"Testing alphabet: {letter}")
            chipertext = encrypt_chosen_plaintext(plaintext=(plaintext + cookie + letter), token=token, url=url)
            chipertext = chipertext[:20]

            if (chipertext == chipertext_test):
                cookie = cookie + letter
                break

    #print(cookie)
    # response = get_challenge -> response.json()
    # challenge = Challenge(**response)


    # Step 2: Get challange
    url_challenge = "http://10.0.15.2/ecb/challenge"
    challange_chyper = get_challenge(url_challenge)
    challenge = Challenge(**challange_chyper)
    #print(challange_chyper)

    key = derive_key(key_seed=cookie)
    #print(key)

    recovered_plaintext = decrypt_challenge(key=key, challenge=challenge)
    print(recovered_plaintext)