# En este ejercicio tenéis que trabajar con el XOR en Python como mecanismo 
# para codificar / proteger información. 
# A continuación se detalla el escenario:

#Tenemos un mensaje cifrado.
#El mensaje cifrado es: 9c8d968f8b90a08f868b979091a0c5bb
#La clave es: ffffffffffffffffffffffffffffffff

#xor 0 0 -> 0 || 0 1 -> 1 || 1 0 -> 1 || 1 1 -> 0

def xor_master(mensaje, key_hex):
    
    ciphertext = bytes.fromhex(mensaje)
    key = bytes.fromhex(key_hex)
    plaintext = b""
    for i in range(len(ciphertext)):
        plaintext += bytes([ciphertext[i] ^ key[i % len(key)]])
    return plaintext.decode("utf-8")

# Ejemplo de uso
ciphertext_hex = "9c8d968f8b90a08f868b979091a0c5bb"
key_hex = "ffffffffffffffffffffffffffffffff"
plaintext = xor_master(ciphertext_hex, key_hex)
print("El mensaje descifrado es:", plaintext)
