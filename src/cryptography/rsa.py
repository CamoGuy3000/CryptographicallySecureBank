
from secrets import randbits
from generate_keys import get_keys
from gen_random_input import generate_random_binary_strings

BIT_SIZE = 1024

# TODO Change project structure if we need to
# Writing the inital RSA scheme here, we can move stuff around later if we want to.

#! CHANGE THIS TO A REAL HASH FUNCTION
def hash(a):
  return a


# custom xor function
# takes in two strings a and b of size length
def xor(a, b, length):
  if(len(a) != len(b) or len(a) != length):
    print("XOR FUNCTION: INVALID INPUT") # TODO what should we do here
    exit(1)
  new = ""
  for i in range(length):
    new += str(int(a[i])^int(b[i]))
  return new


def format_input(inp : list[str]):
  # print({f"inp: {inp}"})
  length = bin(len(inp))[2:]
  # print(f"len: {length}")
  length = "0"*(8 - len(length)) + (length)
  # print(f"len: {length}")
  padding = randbits(BIT_SIZE - len(inp)*8 - 8)
  # print(f"padding: {padding}")
  padding = "0"*(BIT_SIZE - len(inp)*8 - 8 - len(bin(padding)[2:])) + (bin(padding)[2:])
  # print(f"padding: {padding}")

  formatted = inp

  for i in range(0, len(padding), 8):
    formatted.append(padding[i:i+8])
  formatted.append(length)
  # print(formatted)
  # print(len(formatted))
  
  return formatted

# Will encrypt a message (as sender) given the recipient's public keys (n_r and e_r)
# ptxt should be a list of binary strings
# n_r and e_r should be positive integers
# Will return the ctxt, which consists of (encrypted random number, ptxt xor hash(r), hash(ptxt)?)
def encrypt(ptxt, n_r, e_r):
  fptxt = format_input(ptxt)
  #! r IS CURRENTLY CREATED FORM A PYTHON LIBRARY! CHANGE THIS IF NEEDED
  r: int = randbits(BIT_SIZE) % n_r
  # print(f"init r: {r}")
  hash_input: str = "0"*(BIT_SIZE - len(bin(r)[2:])) + (bin(r)[2:]) # Padded with 0's because of how python formats binary numbers (doesn't include leading 0's)
  hashed_r = hash(hash_input) # change hash_input's format when we know how we are calling the hash
  # print(hashed_r)

  # part 1 of ctxt
  re: int = pow(int(r), e_r, n_r) # r^e % n

  C: list = [] # part 2 of ctxt
  for i, m in enumerate(fptxt):
    # print(m, hashed_r[(i*8):(i*8)+8])
    C.append(xor(m, hashed_r[(i*8):(i*8)+8], 8)) # xor the message block with the hashed r

  hashed_ptxt: int = hash(fptxt) # part 3 of ctxt

  # print(f"init r: {r}\nr^e: {re}")
  ctxt: tuple[int, list, int] = (re, C, hashed_ptxt) # create the ctxt
  # print(f"ctxt: {ctxt}\n")

  return ctxt

# Will decrypt a message (as reciver) given it's own private keys (p, q, and d)
# ctxt should be a list of binary strings
# p, q, and d should be positive integers
def decrypt(ctxt, p, q, d):
  n = p * q
  recv_calc_r = pow(ctxt[0], d, n)

  # print(f"recv_r = {recv_calc_r}")
  recv_calc_hash_input = "0"*(BIT_SIZE - len(bin(recv_calc_r)[2:])) + (bin(recv_calc_r)[2:])
  # print(f"recv_hash = {recv_calc_hash_input}")
  recv_calc_hash_r = hash(recv_calc_hash_input)
  # print(f"recv_hash_r = {recv_calc_hash_r}")

  # print(recv_calc_hash_r)
  recv_msg = []
  for i, c in enumerate(ctxt[1]):
    # print(c, recv_calc_hash_r[(i*8):(i*8)+8])
    recv_msg.append(xor(c, recv_calc_hash_r[(i*8):(i*8)+8], 8))
  
  # print(f"D(ctxt): {recv_msg}")

  # Now we have to extract the correct amount of chunks

  length = int(recv_msg[len(recv_msg)-1], 2)
  # print(length)
  message = recv_msg[0:length] # entire message
  #! ^^^ this is what matches the hashed ptxt
  print(f"\nCorrected decrypted message: {message}")
  return message



p, q, n, e, d = get_keys(BIT_SIZE)
# msg = ["01011010", "01001011"]
msg = generate_random_binary_strings(100, 101)
print(f"msg: {msg}")
ogmsg = []
for i in msg:
  ogmsg.append(i)
ctxt = encrypt(msg, n, e)
decrypted = decrypt(ctxt, p, q, d)

print(f"Is the decrypted message correct?\n{'Yes!' if decrypted == ogmsg else 'No :('}")

