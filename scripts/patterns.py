#!/usr/bin/python3

PIN_PATTERNS = [# 
#  1234567890123456789012345678901234567890123456789012345678901234567890123
  ".xx.xxx...x..xx..x..xxxx..xxx.x.x.xxx..xx..xxx.xx.....xxx...xxxx.x......x", # A73\
  ".xxxx..xxxxxx...x...x.x..xx.xxxxx.....xxx...xx.xxx.....xx.x.x.xxx.....x",   # B71\
  ".xxxxx.x.xx..x.xx....xx.x....xxxx.xxx.xxx...x..x..xxx....xx....xx...x",     # C69\
  ".xx.x.x...xxx.....xx.x....x..xxx..xxx..x.xxx...xx..x..x.xxxx..x...x",       # D67\
  ".x...x...x.xxxxxxx.x.xxxxxx..x.x..xx.x....x.xxxxx..xxx.x.x.xx...x",         # E65\
  ".x.x.xxxxx....x.xxxx..x.xx.xxxx.xx..xxx....x....xxx.xxxxxx...x.x",          # F64\
  ".xxxx...xx..xx...x.xxxxx.x..x..xxx.x.xx.x.xx.x....xx.x..x.xxx",             # G61\
  ".x..xxxxx...xxxx.x..xxxx...xx.x...xx.x.xx...xxxxxx..xx.x.xx",               # H59\
  ".x.xx.xx..xx.x.xx...xxx...xxx..x.xxx.x....xxxx...x.xx",                     # J53 (no I)\
  ".x....xxxxx...x..x.xxx..x.x.xxx..xxx.xxxx...xxx"]                           # K47

for p in PIN_PATTERNS:
  out="{"
  for i in range(80): # Pad all to 80 for abKnownPT
    if i!=0:
      out+=","
    j=i%len(p)
    if (p[j]=="."):
      out+="0"
    else:
      out+="1"

  print (out+"},")

for p in PIN_PATTERNS:
  out="{"
  for i in range(82): # Pad all to 82 for abUnknownPT
    if i!=0:
      out+=","
    j=i%len(p)
    if (p[j]=="."):
      out+="0"
    else:
      out+="1"

  print (out+"},")

for p in PIN_PATTERNS:
  out="{"
  for i in range(106): # Pad all to 106 for cUnknownPT
    if i!=0:
      out+=","
    j=i%len(p)
    if (p[j]=="."):
      out+="0"
    else:
      out+="1"

  print (out+"},")
