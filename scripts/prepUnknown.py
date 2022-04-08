#!/usr/bin/python3

# Generates a script to try all 252 partitions of XOR wheels for given CT
# for unknown PT attack on T52.  The CUDA program T52abUnknownPT only
# addresses one partition at a time so must be invoked 252 times.

# Defaults to GPU 0, but for a multi GPU system you could use different
# GPUs

# Does partitions in order of shortest first as this increaes likelihood of
# finding the solution early.  56789 is shortest as these are the smallest
# wheels
import itertools

CT="GYLRTZAA8QFQIWNVFXPYJDDXFUWCM3UEUJX/FG3KUEWQGBGF+O9C94NUGOIJWPGROO4D9MGKJPKFXWH//DIYWLPYAY+EW/YXY/DANYETL9GIOPDYGOJQ4F+4MIHB8GUW9IY9B4DUA9LGKGUC4VLYRNJYBLHAJBEDE4AB9DHRNRC+FPY/GPDGLWPLEYLFQDUZKBNJW/AWEPQILPN/WYENKNMLCGYDHKNO+UPZSHJ4DTN9FGOBNS+OTSQXQF/WTKMHZP4JWZP9RNG8ONUYMZOV94THOOWIMTMCWWVO9DVSAQDX3MSBEZOPXVYBOKB+YDXWYJP/NHCA3QKEPJ/VQWJRGJBVEE3UCTDMNMSTZ/DSTOFQ9ATQYLPFYHHMCFIKK+UYEOUWOSEPWFXGDYFQXB+8DA4UPFRIQQM4WDC9KGAZ9ICPCGQPZ8PKSJU998TXMIXYNILKC9QHB9EECIA8ZBNIS3XOGQ9ZS398I+MKFQX9KT4MF94PVVZJ"
# This CT has wheels 0,1,2,3,4 as the XOR wheels and 1,2,3,4,5 as the respective offsets.

combs=reversed(sorted(list(itertools.combinations('0123456789',5)))) #10 choose 5

for c in combs:
  print ("./T52abUnknownPT 0 "+''.join(i for i in c)+" "+CT)
