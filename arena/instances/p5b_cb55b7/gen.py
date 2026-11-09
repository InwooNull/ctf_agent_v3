import json, secrets

m = 17525515125609493021
a = 2841345059316064604
c = 15702072447728311369
s = secrets.randbelow(m)          # secret seed

def nxt():
    global s
    s = (a * s + c) % m
    return s

outputs = [nxt() >> 32 for _ in range(6)]        # only the high 32 bits are published
flag = open("flag.txt", "rb").read().strip()
ct = bytes(b ^ (nxt() >> 56) for b in flag)
json.dump({"outputs": outputs}, open("outputs.json", "w"))
open("ct.bin", "wb").write(ct)
