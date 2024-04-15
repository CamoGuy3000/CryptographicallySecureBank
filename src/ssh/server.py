#! /usr/bin/env python
# server.py

import socket
import random
import binascii
import struct
from ssh.utils import open_keyfile
from cryptography.our_rsa import rsa_encrypt
from ssh.kex import KEX
from cryptography.our_sha import my_sha1

class SSHServer:
    # what it sounds like.

    def __init__(self, port=12345):
        self._socket = None
        self._host = socket.gethostbyname(socket.gethostname())
        # self._host = "127.0.0.1"
        self._port = port

    def listen(self):
        self.stop()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((self._host, self._port))
        self._socket.listen(0)

    def poll(self):
        if self._socket is None: return
        print("here")
        conn, addr = self._socket.accept()
        print("here2")
        with conn:
            print("here3")
            print(f"Connected by {addr}")

            # ephemeral diffie hellman
            client_dh = int.from_bytes(conn.recv(256), byteorder='big')
            print(f"Client public DH: {client_dh}")
            public_dh = KEX.create_key()
            print(f"My public DH: {public_dh}")
            conn.sendall(public_dh.to_bytes(256, byteorder='big'))
            shared_secret = KEX.shared_secret(client_dh)
            print(f"Shared secret: {shared_secret}")

            # send host public key for verification
            public_key_params = open_keyfile("../keys/bank.pub")[0][1][1][1]
            if public_key_params['unused_bits'] != 0:
                raise ValueError("Cannot handle unused bits :(")
            n = public_key_params['data'][0][1][0][1]
            e = public_key_params['data'][0][1][1][1] # 65537
            
            print(f"Bank Modulus: {n}")
            print(f"Bank Exponent: {e}")
            conn.sendall(n.to_bytes(129))
            conn.sendall(e.to_bytes(3))

            # compute session hash
            client_cookie = conn.recv(256)
            cookie = random.getrandbits(16).to_bytes(2)
            conn.sendall(cookie)
            print(f"Cookies:")
            print(f"\tClient: {client_cookie}")
            print(f"\tServer: {cookie}")
            client_payload = KEX.compute_kexinit_payload(client_cookie)
            server_payload = KEX.compute_kexinit_payload(cookie)
            hash_list = [ KEX.version_string*2, client_payload, server_payload,
                          e.to_bytes(3), n.to_bytes(129),
                          client_dh.to_bytes(256), public_dh.to_bytes(256),
                          shared_secret.to_bytes((shared_secret.bit_length()+7)//8)]
            session_hash = my_sha1(b''.join(hash_list))
            print(f"Session hash: {session_hash}")

            # read private key to authenticate server to client
            private_key_params = open_keyfile("../keys/bank")[0][1][2]
            private_exp = private_key_params[1][0][1][3][1]
            private_mod = private_key_params[1][0][1][1][1]
            rsa_enc = list(bytes(session_hash, 'utf-8'))
            re, ctxt, hashed = rsa_encrypt(list(bytes(session_hash, 'utf-8')),
                                        private_mod, private_exp)
            re_bytes = re.to_bytes((re.bit_length() + 7) // 8, 'big')
            ctxt_bytes = b''.join([int(b, 2).to_bytes((len(b) + 7) // 8, 'big') for b in ctxt])
            hashed_bytes = bytes.fromhex(hashed)
            message = len(re_bytes).to_bytes(2, 'big') + re_bytes + \
                      len(ctxt_bytes).to_bytes(2, 'big') + ctxt_bytes + \
                      len(hashed_bytes).to_bytes(2, 'big') + hashed_bytes
            conn.sendall(message)
            print(f"Sent\n\tre:{re}\n\tctxt: {ctxt_bytes}\n\thash: {hashed}")

            # need to set up encryption now
            server_IV = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                                bytes(session_hash, 'utf-8') + b'B' +
                                bytes(session_hash, 'utf-8'))

            server_key = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                                 bytes(session_hash, 'utf-8') + b'D' +
                                 bytes(session_hash, 'utf-8'))

            server_hmac = my_sha1(shared_secret.to_bytes((shared_secret.bit_length()+7)//8) +
                                  bytes(session_hash, 'utf-8') + b'F' +
                                  bytes(session_hash, 'utf-8'))

            # from now on, all msgs are encrypted

            # ATM authentication
            # recv public key
            recv_e = int.from_bytes(conn.recv(3))
            recv_n = int.from_bytes(conn.recv(129))
            # compare to known public key
            atm_public_key_params = open_keyfile("../keys/atm.pub")[0][1][1][1]
            if atm_public_key_params['unused_bits'] != 0:
                raise ValueError("Cannot handle unused bits :(")
            atm_n = atm_public_key_params['data'][0][1][0][1]
            atm_e = atm_public_key_params['data'][0][1][1][1] # 65537
            if (recv_e != atm_e or
                recv_n != atm_n):
               print("Unknown public key!")
               self.stop()
            else:
                print(f"ATM Modulus: {atm_n}")
                print(f"ATM Exponent: {atm_e}")







    def stop(self):
        if self._socket is None: return
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
