#! /usr/bin/env python
# client.py

import socket
# import struct
import random
from ssh.kex import KEX
from cryptography.sha import my_sha1

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
        server_exp = int.from_bytes(self._socket.recv(3))
        server_mod = int.from_bytes(self._socket.recv(129))
        print(f"Bank Exponent: {server_exp}")
        print(f"Bank Modulus Len: {server_mod}")

        # compute session hash
        cookie = random.getrandbits(16).to_bytes(2)
        self._socket.sendall(cookie)
        server_cookie = self._socket.recv(2)
        print(f"Cookies:")
        print(f"\tClient: {cookie}")
        print(f"\tServer: {server_cookie}")
        client_payload = KEX.compute_kexinit_payload(cookie)
        server_payload = KEX.compute_kexinit_payload(server_cookie)
        session_hash = my_sha1(KEX.version_string*2 +
                               client_payload +
                               server_payload +
                               server_exp +
                               server_mod +
                               public_dh +
                               server_dh +
                               shared_secret)



    def disconnect(self):
        if self._socket is None: return
        self._socket.close()
