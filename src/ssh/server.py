#! /usr/bin/env python
# server.py

import socket
from ssh.packet import Packet

class SSHServer:
    # what it sounds like.

    def __init__(self, port=54321):
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
            # data = Packet.read_packet(conn)
            # print(f"Data has length {len(data)} bytes")
                # data = conn.recv(1024)
                # if not data:
                #     break
                # conn.sendall(data)

    def stop(self):
        if self._socket is None: return
        self._socket.close()
