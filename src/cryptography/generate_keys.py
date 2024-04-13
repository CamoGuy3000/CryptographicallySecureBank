
from Crypto.Util.number import getPrime

def compute_mod_inverse(e, phi):
  """ Compute the modular inverse of e under modulo phi. """
  # Using Extended Euclidean Algorithm
  d, x1, x2, y1 = 0, 0, 1, 1
  temp_phi = phi
  while e > 0:
    temp1 = temp_phi // e
    temp2 = temp_phi - temp1 * e
    temp_phi, e = e, temp2
    x = x2 - temp1 * x1
    y = d - temp1 * y1
    x2, x1 = x1, x
    d, y1 = y1, y
  if temp_phi == 1:
    return d + phi

def get_keys(size): # returns p, q, n, e, d
  # Parameters
  key_size = size  # size of the prime numbers p and q

  # Generate two large primes p and q
  p = getPrime(key_size)
  q = getPrime(key_size)
  while p == q:
      q = getPrime(key_size)

  # Compute n and phi(n)
  n = p * q
  phi_n = (p - 1) * (q - 1)

  # Public exponent
  e = 65537

  # Private exponent
  d = compute_mod_inverse(e, phi_n)

  # print("p =", p)
  # print("q =", q)
  # print("n = p * q =", n)
  # print("e =", e)
  # print("d =", d)

  return p,q,n,e,d


