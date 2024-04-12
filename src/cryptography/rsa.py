
# TODO Change project structure if we need to
# Writing the inital RSA scheme here, we can move stuff around later if we want to.


# Will encrypt a message (as sender) given the recipient's public keys (n_r and e_r)
# ptxt should be a list of binary strings
# n_r and e_r should be positive integers
# Will return the ctxt, which consists of (encrypted random number, ptxt xor hash(r), hash(ptxt)?)
def encrypt(ptxt, n_r, e_r):
  pass

# Will decrypt a message (as reciver) given it's own private keys (p, q, and d)
# xtct should be a list of binary strings
# p, q, and d should be positive integers
def decrypt(ctxt, p, q, d):
  pass

