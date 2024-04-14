#! /usr/bin/env python

import hashlib
import random
import struct

class KEX:
    # RFC3526 - safe prime
    prime = 0x00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    private_key = 0
    generator = 2

    # version string
    version_string = "SSH-2.0-CryptoBank_1.0"

    # alg list
    kex_algorithms = "diffie-hellman-group14-sha1"
    server_host_key_algorithms = "ssh-rsa"
    encryption_algorithms = "aes128-cbc"
    mac_algorithms = "hmac-sha1"
    compression_algorithms = "none"
    languages = ""

    # computed by both server and client
    @staticmethod
    def create_key():
        KEX.private_key = random.getrandbits(640)
        key = pow(KEX.generator, KEX.private_key, KEX.prime)
        return key

    @staticmethod
    def shared_secret(other_dh):
        return pow(other_dh, KEX.private_key, KEX.prime)

    @staticmethod
    def pack_string(s):
        return struct.pack("!I", len(s)) + s.encode()

    @staticmethod
    def compute_kexinit_payload(cookie):
        payload = struct.pack('!B', 0x14) + cookie
        payload += KEX.pack_string(KEX.kex_algorithms)
        payload += KEX.pack_string(KEX.server_host_key_algorithms)
        payload += KEX.pack_string(KEX.encryption_algorithms)
        payload += KEX.pack_string(KEX.encryption_algorithms)
        payload += KEX.pack_string(KEX.mac_algorithms)
        payload += KEX.pack_string(KEX.mac_algorithms)
        payload += KEX.pack_string(KEX.compression_algorithms)
        payload += KEX.pack_string(KEX.compression_algorithms)
        payload += KEX.pack_string(KEX.languages)
        payload += KEX.pack_string(KEX.languages)
        payload += struct.pack(">B", 0)  # First KEX packet follows
        payload += struct.pack(">I", 0)  # Reserved


    # client
    # @staticmethod
    # def decrypt_kex(keyex):
    #     # S receives e. It computes K = e^y mod p,
    #     if (sys.byteorder == 'little'): # network order -> host order
    #         keyex = int.from_bytes(keyex.to_bytes(math.ceil(keyex.bit_length()/8)), "little")

        # decrypted = pow(keyex, KEX.private_key, KEX.prime)
    

    # sha1 = hashlib.sha1();
    # sha1.update(b"Nobody expects the Spanish inquisition!")
    # sha1.digest(); # returns hash as bytes object
    # sha1.hexdigest(); # returns hash as string object of double length; safe in non-binary env
