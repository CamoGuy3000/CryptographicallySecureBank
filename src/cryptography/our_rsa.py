from secrets import randbits
# from generate_keys import get_keys
# from gen_random_input import generate_random_binary_strings

from cryptography.our_hmac import hmac_sha1

BIT_SIZE = 1024

# TODO Change project structure if we need to
# Writing the inital RSA scheme here, we can move stuff around later if we want to.

# Input should be a string
def hash(a):
  a = bytes(a, "utf-8")
  a = hmac_sha1(b'\x06\xf4L\x91\x88x\xad\xee\x91\x10$\x88\xc6%\x13\xfaS\x0fq*_\x94\xb4\x99\xf5\x14;\xa6\xdfIL6\xe4\xc0M\xb6\x0c\x99\x8bi\xcb\x1fR]\x83/\x08\x93LKh|%\x06"Z\xf2\xf68e\xcc\x15f<', a)
  # print(str(a)[2:-1])
  # print(a)
  return a


# custom xor function
# takes in two strings a and b of size length
def xor(a, b, length):
  if(len(a) != len(b) or len(a) != length):
    print("XOR FUNCTION: INVALID INPUT") # TODO what should we do here
    print(a, b)
    exit(1)
  new = ""
  for i in range(length):
    new += str(int(a[i])^int(b[i]))
  return new


def format_input(inp : list[str]):
  length = bin(len(inp))[2:] 
  length = "0"*(8 - len(length)) + (length)     
  # num of strings in list as binary

  padding = randbits(BIT_SIZE - len(inp)*8 - 8) 
  padding = "0"*(BIT_SIZE - len(inp)*8 - 8 - len(bin(padding)[2:])) + (bin(padding)[2:])
  # random padding 

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
# Will return the ctxt, which consists of (encrypted random number, ptxt xor hash(r), hash(ctxt + r))
def rsa_encrypt(ptxt, n_r, e_r):
  # convert from bin strs to strs of binary...
  ptxt = [ format(x, '08b') for x in ptxt ]

  fptxt = format_input(ptxt)
  #! r IS CURRENTLY CREATED FORM A PYTHON LIBRARY! CHANGE THIS IF NEEDED
  r: int = randbits(BIT_SIZE) % n_r
  # print(f"init r: {r}")
  hash_input: str = "0"*(BIT_SIZE - len(bin(r)[2:])) + (bin(r)[2:]) # Padded with 0's because of how python formats binary numbers (doesn't include leading 0's)
  hashed_r: str = hash(hash_input)
  bin_hashed_r = (bin(int(hashed_r, 16))[2:130])*8
  # print(f"Hashed_r: {hashed_r}")
  # print(f"Bin Hashed_r: {bin_hashed_r}, len = {len(bin_hashed_r)}")
  # part 1 of ctxt
  re: int = pow(int(r), e_r, n_r) # r^e % n

  C: list = [] # part 2 of ctxt
  for i, m in enumerate(fptxt):
    # print(m, hashed_r[(i*8):(i*8)+8])
    # print(i*8, i*8+8)
    # print(m, bin_hashed_r[i*8:i*8+8])
    C.append(xor(m, bin_hashed_r[(i*8):((i*8)+8)], 8)) # xor the message block with the hashed r

  hashing = ''.join(str(int(c, 2)) for c in C) + str(r)
  hashed_ctxt_r = hash(hashing) # part 3 of ctxt
  # print(f"hashedptxt: {hashed_ctxt_r}")

  # print(f"init r: {r}\nr^e: {re}")
  ctxt: tuple[int, list, str] = (re, C, hashed_ctxt_r) # create the ctxt
  # print(f"ctxt: {ctxt}\n")

  return ctxt

# Will decrypt a message (as reciver) given it's own private keys (p, q, and d)
# ctxt should be a list of binary strings
# p, q, and d should be positive integers
def rsa_decrypt(ctxt, p, q, d):
  # convert ctxt from bytes to string of binary
  ctxt = ( ctxt[0], [ format(x, '08b') for x in ctxt[1] ], ctxt[2] )

  n = p * q
  recv_calc_r = pow(ctxt[0], d, n)

  # print(f"recv_r = {recv_calc_r}")
  recv_calc_hash_input = "0"*(BIT_SIZE - len(bin(recv_calc_r)[2:])) + (bin(recv_calc_r)[2:])
  # print(f"recv_hash = {recv_calc_hash_input}")
  recv_calc_hash_r = hash(recv_calc_hash_input)
  recv_bin_hash_r = (bin(int(recv_calc_hash_r, 16))[2:130])*8
  # print(f"recv_hash_r = {recv_calc_hash_r}")

  # print(recv_calc_hash_r)
  recv_msg = []
  for i, c in enumerate(ctxt[1]):
    # print(c, recv_calc_hash_r[(i*8):(i*8)+8])
    recv_msg.append(xor(c, recv_bin_hash_r[(i*8):(i*8)+8], 8))
  
  # print(f"D(ctxt): {recv_msg}")

  # Now we have to extract the correct amount of chunks

  length = int(recv_msg[len(recv_msg)-1], 2)
  # print(length)
  message = recv_msg[0:length] # entire message
  #! ^^^ this is what matches the hashed ptxt
  # print(f"Corrected decrypted message: {message}")
  return recv_calc_r, message


def rsa_verify(ctxt, r, recv_hash):
  ctxt = [ format(x, '08b') for x in ctxt ]
  hashing = ''.join(str(int(c, 2)) for c in ctxt) + str(r)
  # hashing = str(int.from_bytes(ctxt)) + str(r)
  if(hash(hashing) == recv_hash):
    return True
  return False



# p, q, n, e, d = get_keys(BIT_SIZE)
# msg = ["01011010", "01001011"]
# # length = 100
# # msg = generate_random_binary_strings(length, length)
# print(f"msg: {msg}")
# ogmsg = []
# for i in msg:
#   ogmsg.append(i)
# ctxt = rsa_encrypt(msg, n, e)
# r, decrypted = rsa_decrypt(ctxt, p, q, d)

# print(f"decrypted message: {decrypted}")
# print(f"Is the decrypted message correct? {'Yes!' if decrypted == ogmsg else 'No :('}")

# print(rsa_varify(ctxt[1], r, ctxt[2]))

