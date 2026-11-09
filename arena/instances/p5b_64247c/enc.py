import json, secrets

MASK = 0xffffffff
MUL = 0x2545F491

def rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK

def round_key(k, r):
    return (k * 0x9E3779B1 + r * 0x7F4A7C15) & MASK

def E(k, x):                       # 32-bit block, 18-bit key
    for r in range(6):
        x = (x + round_key(k, r)) & MASK
        x = rotl(x, 7) ^ 0xA5A5A5A5
        x = (x * MUL) & MASK
    return x

def enc(k1, k2, x):                # "double strength"
    return E(k2, E(k1, x))

k1 = secrets.randbelow(1 << 18)    # secret
k2 = secrets.randbelow(1 << 18)    # secret
pts = [secrets.randbits(32) for _ in range(3)]
json.dump({"pairs": [[p, enc(k1, k2, p)] for p in pts]}, open("pairs.json", "w"))
flag = open("flag.txt", "rb").read().strip()
n = 4 - len(flag) % 4
flag += bytes([n]) * n
ct = b"".join(enc(k1, k2, int.from_bytes(flag[i:i + 4], "big")).to_bytes(4, "big")
              for i in range(0, len(flag), 4))
open("ct.bin", "wb").write(ct)
