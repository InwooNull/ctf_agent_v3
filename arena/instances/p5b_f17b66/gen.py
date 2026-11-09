import json, secrets

m = 17962122177155552377
a = 15046569924305720237
c = 8673763366766677757
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
