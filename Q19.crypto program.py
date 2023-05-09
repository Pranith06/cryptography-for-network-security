from Crypto.Cipher import DES3
import os

def pad(text):
    padding_length = 8 - (len(text) % 8)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def unpad(text):
    padding_length = text[-1]
    return text[:-padding_length]

def encrypt_cbc(plaintext, key):
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_cbc(ciphertext, key):
    iv = ciphertext[:8]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext[8:])
    plaintext = unpad(padded_plaintext)

    return plaintext

plaintext = b"meet me at the usual place at ten rather than eight oclock"
key = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10\x01\x23\x45\x67\x89\xAB\xCD\xEF"
ciphertext = encrypt_cbc(plaintext, key)
decrypted_plaintext = decrypt_cbc(ciphertext, key)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext: {ciphertext}")
print(f"Decrypted plaintext: {decrypted_plaintext}")
