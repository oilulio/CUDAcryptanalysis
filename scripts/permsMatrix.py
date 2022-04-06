#!/usr/bin/python3
import itertools

out=""
idx=0
for p in itertools.permutations([0,1,2,3,4]): # All permutations of 5 bits

  #print p
  out+="{"
  for i in range(5):   # Specific bit
    out+=str(p[i])
    if (i!=4): out+=","

  out+="},"
  
  if (idx%5==4):
    print (out)
    out=""
  idx+=1
  
