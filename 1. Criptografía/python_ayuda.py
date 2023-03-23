
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
    return textoDescifrado.decode("utf-8")

# Ejemplo de uso
textoCifrado = bin.fromhex("9c8d968f8b90a08f868b979091a0c5bb")
key = bin.fomhex("ffffffffffffffffffffffffffffffff")

mensaje_xor = textoCifrado[2:]^key[2:]
print("El mensaje descifrado es:", mensaje_xor) 




