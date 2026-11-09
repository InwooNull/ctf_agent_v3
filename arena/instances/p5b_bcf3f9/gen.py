# The generator below produced outputs.json and ct.bin. Its parameters were not saved.
import json, os

m = ...   # secret 64-bit prime
a = ...   # secret, 0 < a < m
c = ...   # secret, 0 <= c < m
x = ...   # secret seed

def nxt():
    global x
    x = (a * x + c) % m
    return x

outputs = [nxt() for _ in range(8)]
flag = open("flag.txt", "rb").read().strip()
ct = bytes(b ^ (nxt() & 0xff) for b in flag)
json.dump({"outputs": outputs}, open("outputs.json", "w"))
open("ct.bin", "wb").write(ct)
