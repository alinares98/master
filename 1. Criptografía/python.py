
#Se tiene un mensaje cifrado.
    #El mensaje cifrado es: 9c8d968f8b90a08f868b979091a0c5bb
    #La clave es: ffffffffffffffffffffffffffffffff
    #xor 0 0 -> 0 || 0 1 -> 1 || 1 0 -> 1 || 1 1 -> 0

def xor_master(mensaje_hex, key_hex):
    
    textoCifrado = bytes.fromhex(mensaje_hex)
    key = bytes.fromhex(key_hex)
    textoDescifrado = b""
    for i in range(len(textoCifrado)):
        textoDescifrado += bytes([textoCifrado[i] ^ key[i % len(key)]])
    return textoDescifrado.decode("ascii")

# Ejemplo de uso
textoCifrado_hex = "9c8d968f8b90a08f868b979091a0c5bb"
key_hex = "ffffffffffffffffffffffffffffffff"
textoPlano = xor_master(textoCifrado_hex, key_hex)
print("El mensaje descifrado es:", textoPlano) 

# resultado -> cripto_python_:D



