#!/usr/bin/python3

# Code generation assist script for combinations

import itertools
index=0
data=""
for comb in list(itertools.combinations('0123456789',4)): #10 choose 4
  data+="{"
  for i in range(4):
    data+=comb[i]
    if (i<3):
      data+=","
  data+="},"
  index+=1
  if (index%8==0 or index==210):
    print (data)
    data=""
  
  
