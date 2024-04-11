from base64 import b64decode

import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel


class Ciphertext(BaseModel):
    nonce: str
    ciphertext: str


class Challenge(BaseModel):
    nonce: str
    ciphertext: str


def get_token(url, username, password):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"username": username, "password": password},
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    return token


def encrypt_chosen_plaintext(url, token, plaintext):
    response = requests.post(
        url=url,
        headers={
            "accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"plaintext": plaintext},
    )
    response.raise_for_status()
    return response.json()


def get_challenge(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    # 1. Get the token
    host = "10.0.15.2"
    path = "ctr/token"
    username = "hrkac_marijana"
    password = "abynouthen"
    url = f"http://{host}/{path}"

    token = get_token(url=url, username=username, password=password)
    print(f"Token: {token}")

    # 2. Get the challenge and prepare plaintext based upon it
    path = "ctr/challenge"
    url = f"http://{host}/{path}"
    challenge = get_challenge(url)
    challenge = Challenge(**challenge)
    challenge_nonce = challenge.nonce

    challenge_ciphertext = b64decode(challenge.ciphertext)
    chosen_ciphertext_length = len(challenge_ciphertext)
    chosen_plaintext = "x" * chosen_ciphertext_length
    print(f"Chosen plaintext: {chosen_plaintext}")

    # 3. Iterate until the nonce repeats
    nonce = None
    chosen_ciphertext = None
    counter = 1

    print("\n")
    path = "ctr/"
    url = f"http://{host}/{path}"
    while challenge_nonce != nonce:
        print(f"[*] Request count: {counter:,}", end="\r")

        response = encrypt_chosen_plaintext(
            url=url, token=token, plaintext=chosen_plaintext
        )
        ciphertext = Ciphertext(**response)
        nonce = ciphertext.nonce
        chosen_ciphertext = b64decode(ciphertext.ciphertext)

        counter += 1

    chosen_ciphertext = int.from_bytes(chosen_ciphertext, byteorder="big")
    chosen_plaintext = int.from_bytes(chosen_plaintext.encode(), byteorder="big")
    challenge_ciphertext = int.from_bytes(challenge_ciphertext, byteorder="big")

    # 4. Decrypt the challenge
    decrypted_challenge = challenge_ciphertext ^ chosen_ciphertext ^ chosen_plaintext
    decrypted_challenge = decrypted_challenge.to_bytes(
        chosen_ciphertext_length, byteorder="big"
    )
    decrypted_challenge = decrypted_challenge.decode()
    print(f"Decrypted challenge: {decrypted_challenge}")