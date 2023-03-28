from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

#Devuelve el mensaje cifrado en modo CBC utilizando la clave y el IV dados.
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

# Ejemplo de uso
key = b'12345678901234567890123456789012'      # Clave 
iv = os.urandom(16)       # Vector de inicialización aleatorio de 16 bytes
message = b'a secret message' # Mensaje a cifrar

# Ciframos el mensaje
ciphertext = aes_cbc_encrypt(key, message, iv)
print('Texto cifrado:', ciphertext)

# Desciframos el mensaje
plaintext = aes_cbc_decrypt(key, ciphertext, iv)
print('Texto original:', plaintext)


