#! /usr/bin/env python
# client.py

from binascii import Error
import socket
import random
from ssh.kex import KEX
from ssh.utils import open_keyfile
from cryptography.our_sha import my_sha1
from cryptography.our_rsa import rsa_decrypt, rsa_verify

class SSHClient:
    # what it sounds like.

    def __init__(self, host=socket.gethostbyname(socket.gethostname()), port=22):
        self._socket = None
        self._host = host
        self._port = port

    def connect(self):
        self.disconnect()

        # TCP connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._host, self._port))

        # ephemeral diffie hellman
        public_dh = KEX.create_key()
        self._socket.sendall(public_dh.to_bytes(256, byteorder='big'))
        print(f"My public DH: {public_dh}")
        server_dh = int.from_bytes(self._socket.recv(256), byteorder='big')
        print(f"Server public DH: {server_dh}")
        shared_secret = KEX.shared_secret(server_dh)
        print(f"Shared secret: {shared_secret}")

        # recv host public key for verification
        server_mod = int.from_bytes(self._socket.recv(129))
        server_exp = int.from_bytes(self._socket.recv(3))
        print(f"Bank Modulus: {server_mod}")
        print(f"Bank Exponent: {server_exp}")
        server_params = open_keyfile("../keys/bank.pub")[0][1][1][1]
        if server_params['unused_bits'] != 0:
            print("Cannot handle unused bits :(")
            self.disconnect()
        if (server_exp != server_params['data'][0][1][1][1] or
            server_mod != server_params['data'][0][1][0][1]):
            print("Server public key is not known.")
            self.disconnect()

        # compute session hash
        cookie = random.getrandbits(16).to_bytes(2)
        self._socket.sendall(cookie)
        server_cookie = self._socket.recv(2)
        print(f"Cookies:")
        print(f"\tClient: {cookie}")
        print(f"\tServer: {server_cookie}")
        client_payload = KEX.compute_kexinit_payload(cookie)
        server_payload = KEX.compute_kexinit_payload(server_cookie)
        hash_list = [ KEX.version_string*2, client_payload, server_payload,
                      server_exp.to_bytes(3), server_mod.to_bytes(129),
                      public_dh.to_bytes(256), server_dh.to_bytes(256),
                      shared_secret.to_bytes((shared_secret.bit_length()+7)//8)]
        session_hash = my_sha1(b''.join(hash_list))
        print(f"Session hash: {session_hash}")

        # authenticate server
        re_length = int.from_bytes(self._socket.recv(2))
        re = int.from_bytes(self._socket.recv(re_length))
        ctxt_length = int.from_bytes(self._socket.recv(2))
        ctxt_bytes = self._socket.recv(ctxt_length)
        hashed_length = int.from_bytes(self._socket.recv(2))
        hashed = self._socket.recv(hashed_length).hex()
        print(f"Received\n\tre: {re}\n\tctxt: {ctxt_bytes}\n\thash: {hashed}")
        # decrypt + check hash
        r, ptxt = rsa_decrypt((re, ctxt_bytes, hashed), server_mod, 1, server_exp)
        ptxt = b''.join([ int(x, 2).to_bytes() for x in ptxt ]).decode()
        print(f"Decrypted r: {r}")
        print(f"Decrypted ptxt (session hash): {ptxt}")
        if rsa_verify(ctxt_bytes, r, hashed): print(f"Hash matches!!!!")
        else:
            print(f"Hash does not match match :((")
            self.disconnect()

        # need to set up encryption now
        client_IV = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                            bytes(session_hash, 'utf-8') + b'B' +
                            bytes(session_hash, 'utf-8'))

        client_key = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                                bytes(session_hash, 'utf-8') + b'D' +
                                bytes(session_hash, 'utf-8'))

        client_hmac = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                                bytes(session_hash, 'utf-8') + b'F' +
                                bytes(session_hash, 'utf-8'))

        # from now on, all msgs are encrypted

        # ATM authentication
        # identify thyself
        atm_public_key_params = open_keyfile("../keys/atm.pub")[0][1][1][1]
        if atm_public_key_params['unused_bits'] != 0:
            raise ValueError("Cannot handle unused bits :(")
        atm_n = atm_public_key_params['data'][0][1][0][1]
        atm_e = atm_public_key_params['data'][0][1][1][1] # 65537
        self._socket.sendall(atm_e.to_bytes(3))
        self._socket.sendall(atm_n.to_bytes(129))
        print(f"ATM Modulus: {atm_n}")
        print(f"ATM Exponent: {atm_e}")

        # get keys
        atm_private_key_params = open_keyfile("../keys/atm")[0][1][2]
        atm_private_exp = atm_private_key_params[1][0][1][3][1]
        atm_private_mod = atm_private_key_params[1][0][1][1][1]


    def disconnect(self):
        if self._socket is None: return
        self._socket.close()
