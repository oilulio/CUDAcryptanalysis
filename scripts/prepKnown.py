#!/usr/bin/python3


# Generates a script to try all 252 partitions of XOR wheels for given CT
# for known PT attack on T52.  The CUDA program T52abKnownPT only
# addresses one partition at a time so must be invoked 252 times.

# Defaults to GPU 0, but for a multi GPU system you could use different
# GPUs

# Does partitions in order of shortest first as this increaes likelihood of
# finding the solution early.  56789 is shortest as these are the smallest
# wheels

import itertools
PT="EVERYTHINGS9COMING9??9MIL???"
CT="VVX3XVIVLGYFRVIF/UURRG9ZAOQ8EK"
# This CT has wheels 5,6,7,8,9 as the XOR wheels and 64,61,59,53,47 as the respective offsets.

combs=reversed(sorted(list(itertools.combinations('0123456789',5)))) #10 choose 5

for c in combs:
  print ("./T52abKnownPT 0 "+''.join(i for i in c)+" "+PT+" "+CT)
