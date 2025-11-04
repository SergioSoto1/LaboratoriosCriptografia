import base64
from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def ajustar_clave(clave:bytes,largo:int,algoritmo:str) -> bytes:
    if len(clave) < largo:
        clave = clave + get_random_bytes(largo - len(clave))
    elif len(clave) > largo:
        clave = clave[:largo]

    if algoritmo == "3DES":
        if len(clave) not in (16, 24):
            clave = (clave + get_random_bytes(24 - len(clave)))[:24]
        clave = DES3.adjust_key_parity(clave)
    return clave

def ajustar_iv(iv: bytes, largo: int) -> bytes:
    if len(iv) < largo:
        iv = iv + get_random_bytes(largo - len(iv))
    elif len(iv) > largo:
        iv = iv[:largo]
    return iv

def cifrar_cbc(nombre: str, key: bytes, iv: bytes, texto: bytes) -> bytes:
    if nombre == "DES":
        return DES.new(key, DES.MODE_CBC, iv).encrypt(pad(texto, 8))
    if nombre == "AES-256":
        return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(texto, 16))
    return DES3.new(key, DES3.MODE_CBC, iv).encrypt(pad(texto, 8))

def descifrar_cbc(nombre: str, key: bytes, iv: bytes, texto_cifrado: bytes) -> bytes:
    if nombre == "DES":
        return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(texto_cifrado), 8)
    if nombre == "AES-256":
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(texto_cifrado), 16)
    return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(texto_cifrado), 8)

def correr_alg(nombre: str, key_largo: int, iv_largo: int, key_in: str, iv_in: str, texto_in: str):
    key = ajustar_clave(key_in.encode("utf-8"), key_largo, nombre)
    iv  = ajustar_iv(iv_in.encode("utf-8"), iv_largo)
    texto_plano  = texto_in.encode("utf-8")
    texto_cifrado  = cifrar_cbc(nombre, key, iv, texto_plano)
    texto_decifrado  = descifrar_cbc(nombre, key, iv, texto_cifrado)

    print(f"{nombre} (CBC)")
    print(f"clave en hex: {key.hex()}")
    print(f"IV en hex:  {iv.hex()}")
    print(f"Base64: {base64.b64encode(texto_cifrado).decode()}")
    print(f"Descifrado: {texto_decifrado.decode('utf-8')}")
    print(f"Verificación:{' esta bien' if texto_decifrado == texto_plano else 'esta mal'}")

def main():
    texto = input("Texto a cifrar(para todos): ")
    des_key = input("\nKEY DES: ")
    des_iv  = input("IV  DES: ")
    correr_alg("DES", 8, 8, des_key, des_iv, texto)

    aes_key = input("\nKEY AES-256: ")
    aes_iv  = input("IV  AES-256: ")
    correr_alg("AES-256", 32, 16, aes_key, aes_iv, texto)

    tdes_key = input("\nKEY 3DES: ")
    tdes_iv  = input("IV  3DES: ")
    correr_alg("3DES", 24, 8, tdes_key, tdes_iv, texto)

if __name__ == "__main__":
    main()
