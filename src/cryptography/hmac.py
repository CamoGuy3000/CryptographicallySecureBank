
from sha import my_sha1


# Input needs to be two byte strings (b'string_here'), returns a string
def hmac_sha1(key, message) -> str:
  block_size = 64  # Block size for SHA-1 in bytes
  print(f"HMAC_SHA1 init: {key} {message}\n")
  # Ensure key is block size in length
  if len(key) > block_size:
    key = my_sha1(key)
  if len(key) < block_size:
    key += b'\x00' * (block_size - len(key))
  # print(f"key: {key}\n")

  # Create outer and inner padding
  opad = bytes((x ^ 0x5c) for x in key)
  ipad = bytes((x ^ 0x36) for x in key)

  # Perform inner SHA-1
  # print(f"{sha1(ipad+message).hex()}\n{my_sha1(ipad + message)}\n")
  # inner_hash = sha1(ipad + message)
  inner_hash = bytes.fromhex(my_sha1(ipad + message))

  # Perform outer SHA-1
  # print(f"{sha1(opad+inner_hash.encode()).hex()}\n{my_sha1(str(opad) + inner_hash)}\n")
  # final_hash = sha1(opad + inner_hash)
  final_hash = my_sha1(opad + inner_hash)

  # print(f"o: {opad}\ni: {ipad}\ninner: {inner_hash.hex()}\n     {minner_hash}\nfinal: {final_hash.hex()}\n       {mfinal_hash}\n")

  # Return final hash as hexadecimal string
  # return final_hash.hex()
  return final_hash


secret_key = b'secret_key'
message = b'Hello'
hmac_signature = hmac_sha1(secret_key, message)
print('HMAC-SHA1 hash:', hmac_signature)

print(hmac_signature == "f8b6b3ee753fe1d8052cf317b0b4606089c85b19") # with sha 1
# print(hmac_signature == "52460d22ec7e402dc8c62aeda51ec920") # with md5

# print(sha1(b"hello").hex())
# print(my_sha1(b"hello"))
