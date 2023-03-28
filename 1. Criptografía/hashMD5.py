from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def calcular_hash_md5_archivos():
    with open('WinMD5.exe', 'rb') as archivo:
        contenido = archivo.read()
        hash_md5 = hashes.Hash(hashes.MD5(), backend=default_backend())
        hash_md5.update(contenido)
        hash_md5_hex = hash_md5.finalize().hex()
        print(f'Hash MD5 de WinMD5.exe: {hash_md5_hex}')

    with open('WinMD5_2.exe', 'rb') as archivo:
        contenido = archivo.read()
        hash_md5 = hashes.Hash(hashes.MD5(), backend=default_backend())
        hash_md5.update(contenido)
        hash_md5_hex = hash_md5.finalize().hex()
        print(f'Hash MD5 de WinMD5_2.exe: {hash_md5_hex}')

# Llama a la función para calcular los hash MD5 de los archivos
calcular_hash_md5_archivos()
