import json, secrets

m = 16915405816955915699
a = 101948187729792174
c = 3629225275372992176
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
