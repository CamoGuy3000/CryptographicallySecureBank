#! /usr/bin/env python
# server.py

import socket
import random
from sys import byteorder
from ssh.kex import KEX

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


            # compute session hash
            client_cookie = conn.recv(256)
            cookie = random.getrandbits(16).to_bytes(2)
            conn.sendall(cookie)
            print(f"Cookies:")
            print(f"\tClient: {client_cookie}")
            print(f"\tServer: {cookie}")

            client_payload = KEX.compute_kexinit_payload(client_cookie)
            server_payload = KEX.compute_kexinit_payload(cookie)



    def stop(self):
        if self._socket is None: return
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
