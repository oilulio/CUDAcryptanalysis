#!/usr/bin/python3
import itertools

for p in itertools.permutations([0,1,2,3,4]): # All permutations of 5 bits

  #print p
  out="{"
  crosschk=0
  for c in range(32): # All 5 bit patterns
    if (c!=0):
      out+=","
    x=0
    for i in range(5):   # Specific bit
      if (c&(1<<i))!=0:  # was set so ...
        x=x|(1<<p[i])    # ... set its permed equivalent
    out+=str(x)
    crosschk+=x

  print (out+"},")
