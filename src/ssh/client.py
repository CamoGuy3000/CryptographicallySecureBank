#! /usr/bin/env python
# client.py

import socket

class SSHClient:
    # what it sounds like.

    def __init__(self, host=socket.gethostbyname(socket.gethostname()), port=22):
        self._socket = None
        self._host = host
        self._port = port

    def connect(self):
        self.disconnect()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._host, self._port))
        self._socket.sendall(b"12345678")
        # self._socket.sendall(b"Hello, world")
        # data = self._socket.recv(1024)

    def disconnect(self):
        if self._socket is None: return
        self._socket.close()
