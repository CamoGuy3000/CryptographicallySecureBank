
# takes in a string, and returns a string
def my_sha1(data) -> str:
  # Ensure data is in bytes
  if type(data) == str:
    data = data.encode('utf-8')  # encode string to bytes

  # Initial hash values:
  h0 = 0x67452301
  h1 = 0xEFCDAB89
  h2 = 0x98BADCFE
  h3 = 0x10325476
  h4 = 0xC3D2E1F0

  # Padding:
  original_byte_len = len(data)
  original_bit_len = original_byte_len * 8
  data += b'\x80' + b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
  data += original_bit_len.to_bytes(8, 'big')

  def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

  def rol(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

  # Process each 512-bit chunk
  for chunk in chunks(data, 64):
    w = [0] * 80
    # Break chunk into sixteen 32-bit big-endian words
    w[0:16] = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)]

    # Extend the sixteen 32-bit words into eighty 32-bit words
    for i in range(16, 80):
        w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

    a, b, c, d, e = h0, h1, h2, h3, h4

    for i in range(80):
      if 0 <= i < 20:
        f = d ^ (b & (c ^ d))
        k = 0x5A827999
      elif 20 <= i < 40:
        f = b ^ c ^ d
        k = 0x6ED9EBA1
      elif 40 <= i < 60:
        f = (b & c) | (d & (b | c))
        k = 0x8F1BBCDC
      elif 60 <= i < 80:
        f = b ^ c ^ d
        k = 0xCA62C1D6

      temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
      e = d
      d = c
      c = rol(b, 30)
      b = a
      a = temp

    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

  return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# # Example usage
# input_data = "hello"
# output = sha1(input_data)
# print("SHA-1:", output)


