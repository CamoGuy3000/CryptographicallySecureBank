
from secrets import randbits

BIT_SIZE = 8

# TODO Change project structure if we need to
# Writing the inital RSA scheme here, we can move stuff around later if we want to.

#! CHANGE THIS TO A REAL HASH FUNCTION
def hash(a):
  return a


# custom xor function
# takes in two strings a and b of size length
def xor(a, b, length):
  print(a, b, length, type(a), type(b), type(length))
  if(len(a) != len(b) or len(a) != length):
    print("XOR FUNCTION: INVALID INPUT") # TODO what should we do here
    exit(1)
  new = ""
  for i in range(length):
    new += str(int(a[i])^int(b[i]))
  return new


# Will encrypt a message (as sender) given the recipient's public keys (n_r and e_r)
# ptxt should be a list of binary strings
# n_r and e_r should be positive integers
# Will return the ctxt, which consists of (encrypted random number, ptxt xor hash(r), hash(ptxt)?)
def encrypt(ptxt, n_r, e_r):
  #! r IS CURRENTLY CREATED FORM A PYTHON LIBRARY! CHANGE THIS IF NEEDED
  r: int = randbits(BIT_SIZE) #* currently using an 8 bit random number... should change this?
  hash_input: str = "0"*(BIT_SIZE - len(bin(r)[2:])) + (bin(r)[2:]) # Padded with 0's because of how python formats binary numbers (doesn't include leading 0's)
  hashed_r = hash(hash_input) # change hash_input's format when we know how we are calling the hash

  # part 1 of ctxt
  re: int = (int(r)**e_r)%n_r # r^e % n

  C: list = [] # part 2 of ctxt
  for m in ptxt:
    print(m, hashed_r)
    C.append(xor(m, hashed_r, BIT_SIZE)) # xor the message block with the hashed r

  hashed_ptxt: int = hash(ptxt) # part 3 of ctxt

  print(f"init r: {r}\nr^e: {re}")
  ctxt: tuple[int, list, int] = (re, C, hashed_ptxt) # create the ctxt
  print(f"ctxt:    {ctxt}")

  return ctxt

# Will decrypt a message (as reciver) given it's own private keys (p, q, and d)
# xtct should be a list of binary strings
# p, q, and d should be positive integers
def decrypt(ctxt, p, q, d):
  pass


encrypt(["11111111"], 17*23, 7)