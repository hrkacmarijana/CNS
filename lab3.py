import requests
import base64


def get_access_token(username, password, url):
    response = requests.post(
        url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"username": username, "password": password}
    )
    response.raise_for_status()
    return response.json().get("access_token")


def xor_cipher(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != len(plaintext):
        raise ValueError("Key and plaintext lengths must match.")

    ciphertext = bytes(a ^ b for a, b in zip(key, plaintext))
    return ciphertext


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


def get_challenge(url):
    response = requests.get(
        url,
    )
    response.raise_for_status()
    return response.json().get("ciphertext")


def decode_base64_to_bytes(encoded_string: str) -> bytes:
    return base64.b64decode(encoded_string)


if __name__ == "__main__":
    username = "hrkac_marijana"
    password = "ctigengest"
    plaintext = "Cats are smart"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJocmthY19tYXJpamFuYSIsInNjb3BlIjoidmVybmFtIiwiZXhwIjoxNzEwOTQzOTkzfQ.NyTQ2FvmOQzaOWmHkZMSzqC11PExq4ng08nCl4unHl0"
   
    # Step 1: Get the token
    url_token = "http://10.0.15.1/vernam/token"
    token = get_access_token(username, password, url_token)
    # print(token)

    # Step 2: Get challange
    url_challenge = "http://10.0.15.1/vernam/challenge"
    challange_chyper = get_challenge(url_challenge)
   
    # Step 3: Chllenge in bytes
    challenge_in_bytes = decode_base64_to_bytes(challange_chyper)

    # Step 4: Plaintext
    plaintext = len(challenge_in_bytes)*"a"
    url_chiper = "http://10.0.15.1/vernam"
    ciphertext = encrypt_chosen_plaintext(plaintext, token, url_chiper)
    chipertext_in_bytes = decode_base64_to_bytes(ciphertext)
  
    # Step 5: Decrypt the challange
    challange = xor_cipher(xor_cipher(chipertext_in_bytes, challenge_in_bytes), plaintext.encode())
    print(challange)





