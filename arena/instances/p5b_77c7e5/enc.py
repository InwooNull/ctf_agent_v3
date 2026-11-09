import struct
MASK = 0xffffffff

def rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK

def round_keys(key):
    s = int.from_bytes(key[2:4], "big")
    ks = []
    for i in range(8):
        s = (s * 0x9E3779B1 + 0x7F4A7C15 + i) & MASK
        ks.append(s)
    return ks

def F(r, k):
    x = (r + k) & MASK
    x ^= rotl(x, 7) ^ rotl(x, 19)
    return (x * 0x2545F491) & MASK

def encrypt_block(b, ks):
    L, R = struct.unpack(">II", b)
    for k in ks:
        L, R = R, L ^ F(R, k)
    return struct.pack(">II", R, L)

def pad(m):
    n = 8 - len(m) % 8
    return m + bytes([n]) * n

import os
key = os.urandom(8)          # 64-bit key, not saved
ks = round_keys(key)
flag = open("flag.txt", "rb").read().strip()
pt = pad(flag)
ct = b"".join(encrypt_block(pt[i:i + 8], ks) for i in range(0, len(pt), 8))
open("ct.bin", "wb").write(ct)
