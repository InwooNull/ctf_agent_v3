import os

LENGTHS = (12, 15, 16)
TAPS = (3723, 32437, 58229)
states = [int.from_bytes(os.urandom(2), "big") % (1 << L) or 1 for L in LENGTHS]   # secret

def step(i):
    s = states[i]
    out = s & 1
    fb = bin(s & TAPS[i]).count("1") & 1
    states[i] = (s >> 1) | (fb << (LENGTHS[i] - 1))
    return out

def zbit():
    x1, x2, x3 = step(0), step(1), step(2)
    return (x1 & x2) ^ ((1 ^ x1) & x3)

def kbyte():
    return sum(zbit() << j for j in range(8))

msg = b"-----BEGIN MESSAGE-----\n" + open("flag.txt", "rb").read().strip() + b"\n-----END MESSAGE-----\n"
ct = bytes(b ^ kbyte() for b in msg)
open("ct.bin", "wb").write(ct)
