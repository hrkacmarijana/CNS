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
    iv: str
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
    return response.json()


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


def get_wordlist(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.content


def get_encrypted_cookie(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.json()


def get_current_iv(url, token):
    response = encrypt_chosen_plaintext(plaintext=b"bilo sto".hex(), token=token, url=url)
    return response


def add_padding(word: bytes) -> int:
    padder = padding.PKCS7(128).padder()
    padded_word = padder.update(word)
    padded_word += padder.finalize()
    return padded_word


def test_padding():
    for i in range(1, 17):
        word = b"a" * i
        padded_word = add_padding(word)
        print(f"word: {word} ({len(word)} bytes)")
        print(f"padded_word: {padded_word.hex()}\n")


if __name__ == "__main__":
    username = "hrkac_marijana"
    password = "nefirercha"
    # token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJocmthY19tYXJpamFuYSIsInNjb3BlIjoiZWNiIiwiZXhwIjoxNzExNTQ4NTY2fQ.pX1RlFP4q_jzfgpQ3xXRe1YfzTQ-a3P1a9JKHIc4x9w"   
    lowercase_alphabet = string.ascii_lowercase


    # Step 1. Get the token
    url_token = "http://10.0.15.2/cbc/token"
    token = get_access_token(username, password, url_token)
    #print(token)


    #Step 2. Get Encrypted cookie C_V and related IV_V
    url_enc_cookie = "http://10.0.15.2/cbc/iv/encrypted_cookie"
    response = get_encrypted_cookie(url_enc_cookie)
    ciphertext = Ciphertext(**response)
    cookie_iv = b64decode(ciphertext.iv)
    chipertext_iv = b64decode(ciphertext.ciphertext)

    cookie_iv = int.from_bytes(cookie_iv, byteorder="big")
    #print(f"Cookie IV: {cookie_iv}")


    #Step 3. Get the wordlist
    url_wordlist = "http://10.0.15.2/static/wordlist.txt"
    wordlist = get_wordlist(url_wordlist)
    #print(wordlist)


    #Step 4. Learn the IV_next
    url_iv_current = "http://10.0.15.2/cbc/iv"
    response = get_current_iv(url=url_iv_current, token=token)
    ciphertext = Ciphertext(**response)
    current_iv = b64decode(ciphertext.iv)
    current_iv = int.from_bytes(current_iv, byteorder="big")
    #print(f"Current IV: {current_iv}")


    #Step 5. Chosen-plaintext attack (iterate over the worrdlist and text for ctxt collision)
    cookie=""
    for word in wordlist.split():
        #print(f"\nTesting word: {word}")

        # 5.1 Calculate IV_next
        next_iv = current_iv + 4

        # 5.2 Pad the word
        padded_word = add_padding(word)
        #print(f"Padded word: {padded_word.hex()}")
        padded_word = int.from_bytes(padded_word, byteorder="big")

        # 5.3 Prepare chosen plaintext (hex encoded)
        chosen_plaintext = padded_word ^ cookie_iv ^ next_iv
        chosen_plaintext = chosen_plaintext.to_bytes(16, "big").hex()
        print(f"[*] Plaintext: {chosen_plaintext}") 

        # 5.4 Send the chosen plaintext to the server
        response = encrypt_chosen_plaintext(
            plaintext=chosen_plaintext,
            token=token,
            url=url_iv_current,
        )
        
        ciphertext = Ciphertext(**response)
        iv = b64decode(ciphertext.iv)
        ciphertext = b64decode(ciphertext.ciphertext)        
        
        # 5.5 Verify if the candidate word matches the encrypted cookie
        if ciphertext[:16] == chipertext_iv[:16]:
            cookie= word.decode()

        print(f"cookie: {cookie}")
        # 5.6 Update the current IV
        current_iv = int.from_bytes(iv, byteorder="big")
        print(f"[*] Current IV: {current_iv}")

        
    # Step 6: Derive the key from the cookie
    key = derive_key(key_seed=cookie)

    # Step 7: Get the challenge
    url_challenge = "http://10.0.15.2/cbc/iv/challenge"
    response = get_challenge(url_challenge)
    challenge = Challenge(**response)
    
    # Step 8: Decrypt the challenge
    plaintext = decrypt_challenge(key=key, challenge=challenge)
    print(f"\nDecrypted challenge: {plaintext}")
