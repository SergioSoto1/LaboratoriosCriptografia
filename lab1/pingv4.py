from scapy.all import *
import time, random, sys

def enviar_paquetes_icmp(texto_cifrado, destino_ip):
    # Padding fijo (39 bytes) – usaremos 31 para Data=40
    padding = bytearray([
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    ])  # 39 bytes

    icmp_id = 0x2eca
    ip_id_base = random.randint(0, 0xFFFF)

    for seq, char in enumerate(texto_cifrado, start=1):
        # ----- payload de 40 bytes -----
        datos = bytearray(40)

        # [0..7]: timestamp (4B sec + 4B usec) — BE
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1_000_000)
        datos[0:4] = sec.to_bytes(4, 'big')
        datos[4:8] = usec.to_bytes(4, 'big')

        # [8]: carácter cifrado
        datos[8] = ord(char)

        datos[9:] = padding[:39]

        paquete = (
            IP(dst=destino_ip, id=(ip_id_base + seq) & 0xFFFF) /
            ICMP(type=8, code=0, id=icmp_id, seq=seq) /
            Raw(load=bytes(datos))
        )

        print(".")
        send(paquete, verbose=False)
        print("Sent 1 packets.")
        time.sleep(1)

# ---- CLI ----
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Uso: sudo python3 pingv4.py "<texto_cifrado>" [destino_ip]')
        sys.exit(1)
    texto_cifrado = sys.argv[1]
    destino_ip = sys.argv[2] if len(sys.argv) >= 3 else "8.8.8.8"
    enviar_paquetes_icmp(texto_cifrado, destino_ip)
