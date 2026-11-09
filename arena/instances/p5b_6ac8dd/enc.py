import os

TAPS = int.from_bytes(os.urandom(4), "big") | 1        # secret, not saved
state = int.from_bytes(os.urandom(4), "big") or 1      # secret, not saved

def bit():
    global state
    out = state & 1
    fb = bin(state & TAPS).count("1") & 1
    state = (state >> 1) | (fb << 31)
    return out

def keystream_byte():
    v = 0
    for i in range(8):
        v |= bit() << i
    return v

msg = b"MSG v1\n" + open("flag.txt", "rb").read().strip() + b"\n"
ct = bytes(b ^ keystream_byte() for b in msg)
open("ct.bin", "wb").write(ct)
