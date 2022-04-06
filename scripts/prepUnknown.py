#!/usr/bin/python3

CT="DUMMY"

for i in range(100000,0,-1):
  x=i%10
  y=int(i/10)%10
  z=int(i/100)%10
  a=int(i/1000)%10
  b=int(i/10000)%10


  if (x<=y): continue
  if (x<=z): continue
  if (x<=a): continue
  if (x<=b): continue
  if (y<=z): continue
  if (y<=a): continue
  if (y<=b): continue
  if (z<=a): continue
  if (z<=b): continue
  if (a<=b): continue
  #print (x,y,z,a,b)

  print ("./T52abUnknownPT 0 "+str(b)+str(a)+str(z)+str(y)+str(x)+" "+CT)
