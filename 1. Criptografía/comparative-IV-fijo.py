from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

#MODO CBC
def aes_cbc_encrypt(key: bytes, message: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(plaintext_padded) + unpadder.finalize()

#MODO OFB

def aes_ofb_encrypt(key: bytes, message: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_ofb_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

#MODO CFB

def aes_cfb_encrypt(key: bytes, message: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_cfb_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

#MODO ECB

def aes_ecb_encrypt(key: bytes, message: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

#Ejemplo de uso con IV fijo
key = b'12345678901234567890123456789012'     # Clave 
iv_fijo = b'\x00'*16       # Vector de inicialización aleatorio de 16 bytes
message = b'a secret message' # Mensaje a cifrar

print("Mensaje original:", message)

# Modo CBC
ciphertext = aes_cbc_encrypt(key, message, iv_fijo)
print("Texto cifrado (CBC):", ciphertext)
plaintext = aes_cbc_decrypt(key, ciphertext, iv_fijo)
print("Texto original (CBC):", plaintext)

# Modo OFB
ciphertext = aes_ofb_encrypt(key, message, iv_fijo)
print("Texto cifrado (OFB):", ciphertext)
plaintext = aes_ofb_decrypt(key, ciphertext, iv_fijo)
print("Texto original (OFB):", plaintext)

# Modo CFB
ciphertext = aes_cfb_encrypt(key, message, iv_fijo)
print("Texto cifrado (CFB):", ciphertext)
plaintext = aes_cfb_decrypt(key, ciphertext, iv_fijo)
print("Texto original (CFB):", plaintext)

# Modo ECB
ciphertext = aes_ecb_encrypt(key, message)
print("Texto cifrado (ECB):", ciphertext)
plaintext = aes_ecb_decrypt(key, ciphertext)
print("Texto original (ECB):", plaintext)