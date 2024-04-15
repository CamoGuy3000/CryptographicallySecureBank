#! /usr/bin/env python

import socket
from cryptography.our_aes import aes_decrypt, aes_encrypt, aes_verify

class Packet:

    @staticmethod
    def write_packet(sock, data, aes_key, iv, mac_key):
        (_, ctxt, mac) = aes_encrypt(data, aes_key, iv, mac_key)
        ctxt_bytes = b''.join([b.to_bytes() for b in ctxt])
        sock.sendall(ctxt_bytes + mac.encode())

    @staticmethod
    def read_packet(sock, aes_key, iv, mac_key) -> bytes:
        payload_c = sock.recv(16)
        payload = b''.join([int(b, 2).to_bytes()
                            for b in aes_decrypt([ b for b in payload_c ], aes_key, iv)])
        mac = sock.recv(40).decode()

        if not aes_verify(iv, [b for b in payload_c], mac, mac_key):
            print("Failed mac verification")
            return b''
            
        return payload
