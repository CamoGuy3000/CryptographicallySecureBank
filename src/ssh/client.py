#! /usr/bin/env python
# client.py

import socket
import random
import struct
from ssh.kex import KEX
from ssh.utils import open_keyfile, compute_key
from ssh.packet import Packet
from cryptography.our_sha import my_sha1
from cryptography.our_rsa import rsa_encrypt, rsa_decrypt, rsa_verify

class SSHClient:
    # what it sounds like.

    def __init__(self, host=socket.gethostbyname(socket.gethostname()), port=22):
        self._socket = None
        self._host = host
        self._port = port
        self._server_IV = None
        self._server_key = None
        self._server_hmac = None
        self._client_IV = None
        self._client_key = None
        self._client_hmac = None
        self._actions = {
            "1": ("Check balance", 1),
            "2": ("Deposit", 2),
            "3": ("Withdraw", 3),
            "4": ("Quit", 4)
        }

    def connect(self):
        self.disconnect()
        print("Found!")

        # TCP connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((self._host, self._port))

        # ephemeral diffie hellman
        public_dh = KEX.create_key()
        self._socket.sendall(public_dh.to_bytes(256, byteorder='big'))
        # print(f"My public DH: {public_dh}")
        server_dh = int.from_bytes(self._socket.recv(256), byteorder='big')
        # print(f"Server public DH: {server_dh}")
        shared_secret = KEX.shared_secret(server_dh)
        # print(f"Shared secret: {shared_secret}")

        # recv host public key for verification
        server_mod = int.from_bytes(self._socket.recv(129))
        server_exp = int.from_bytes(self._socket.recv(3))
        # print(f"Bank Modulus: {server_mod}")
        # print(f"Bank Exponent: {server_exp}")
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
        # print(f"Cookies:")
        # print(f"\tClient: {cookie}")
        # print(f"\tServer: {server_cookie}")
        client_payload = KEX.compute_kexinit_payload(cookie)
        server_payload = KEX.compute_kexinit_payload(server_cookie)
        hash_list = [ KEX.version_string*2, client_payload, server_payload,
                      server_exp.to_bytes(3), server_mod.to_bytes(129),
                      public_dh.to_bytes(256), server_dh.to_bytes(256),
                      shared_secret.to_bytes((shared_secret.bit_length()+7)//8)]
        session_hash = my_sha1(b''.join(hash_list))
        # print(f"Session hash: {session_hash}")

        # authenticate server
        re_length = int.from_bytes(self._socket.recv(2))
        re = int.from_bytes(self._socket.recv(re_length))
        ctxt_length = int.from_bytes(self._socket.recv(2))
        ctxt_bytes = self._socket.recv(ctxt_length)
        hashed_length = int.from_bytes(self._socket.recv(2))
        hashed = self._socket.recv(hashed_length).hex()
        # print(f"Received\n\tre: {re}\n\tctxt: {ctxt_bytes}\n\thash: {hashed}")
        # decrypt + check hash
        r, ptxt = rsa_decrypt((re, ctxt_bytes, hashed), server_mod, 1, server_exp)
        ptxt = b''.join([ int(x, 2).to_bytes() for x in ptxt ]).decode()
        # print(f"Decrypted r: {r}")
        # print(f"Decrypted ptxt (session hash): {ptxt}")
        if not rsa_verify(ctxt_bytes, r, hashed):
            print(f"Hash does not match match :((")
            self.disconnect()

        # ATM authentication
        # identify thyself
        atm_public_key_params = open_keyfile("../keys/atm.pub")[0][1][1][1]
        if atm_public_key_params['unused_bits'] != 0:
            raise ValueError("Cannot handle unused bits :(")
        atm_n = atm_public_key_params['data'][0][1][0][1]
        atm_e = atm_public_key_params['data'][0][1][1][1] # 65537
        self._socket.sendall(atm_e.to_bytes(3))
        self._socket.sendall(atm_n.to_bytes(129))

        # receive challenge
        # challenge_list = [ session_hash.encode(), random.getrandbits(16).to_bytes(2),
        #                    atm_e.to_bytes(3), atm_n.to_bytes(129), 
        #                    cur_time.to_bytes((cur_time.bit_length()+7)//8) ]
        challenge = self._socket.recv(2 + 3 + 129 + 4)
        challenge = my_sha1(session_hash.encode() + challenge)
        # get keys
        atm_private_key_params = open_keyfile("../keys/atm")[0][1][2]
        atm_private_exp = atm_private_key_params[1][0][1][3][1]
        atm_private_mod = atm_private_key_params[1][0][1][1][1]
        re, ctxt, hashed = rsa_encrypt(list(bytes(session_hash, 'utf-8')),
                                    atm_private_mod, atm_private_exp)
        re_bytes = re.to_bytes((re.bit_length() + 7) // 8, 'big')
        ctxt_bytes = b''.join([int(b, 2).to_bytes((len(b) + 7) // 8, 'big') for b in ctxt])
        hashed_bytes = bytes.fromhex(hashed)
        message = len(re_bytes).to_bytes(2, 'big') + re_bytes + \
                  len(ctxt_bytes).to_bytes(2, 'big') + ctxt_bytes + \
                  len(hashed_bytes).to_bytes(2, 'big') + hashed_bytes
        self._socket.sendall(message)

        # need to set up encryption now
        self._server_IV = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                      bytes(session_hash, 'utf-8'), b'B',
                                      bytes(session_hash, 'utf-8'), 16)
        self._server_IV = [ i for i in self._server_IV.encode() ]

        self._server_key = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                       bytes(session_hash, 'utf-8'), b'D',
                                       bytes(session_hash, 'utf-8'), 16)
        self._server_key = [ format(i, '08b') for i in self._server_key.encode() ]

        self._server_hmac = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                        bytes(session_hash, 'utf-8'), b'F',
                                        bytes(session_hash, 'utf-8'), 64).encode()



        self._client_IV = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                      bytes(session_hash, 'utf-8'), b'A',
                                      bytes(session_hash, 'utf-8'), 16)
        self._client_IV = [ i for i in self._client_IV.encode() ]

        self._client_key = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                       bytes(session_hash, 'utf-8'), b'C',
                                       bytes(session_hash, 'utf-8'), 16)
        self._client_key = [ format(i, '08b') for i in self._client_key.encode() ]

        self._client_hmac = compute_key(shared_secret.to_bytes((shared_secret.bit_length()+7)//8),
                                        bytes(session_hash, 'utf-8'), b'E',
                                        bytes(session_hash, 'utf-8'), 64).encode()

        # from now on, all msgs are encrypted
        # now we can do stuff

    def check_balance(self, choice):
        action, header = self._actions[choice]
        data = [format(i, '08b') for i in header.to_bytes(1) ]
        Packet.write_packet(self._socket, data, self._client_key,
                            self._client_IV, self._client_hmac)
        balance = Packet.read_packet(self._socket, self._server_key,
                                     self._server_IV, self._server_hmac)
        balance = struct.unpack("!I", balance)[0]
        print(f"Balance: {balance}")

    def change_balance(self, choice, amount):
        action, header = self._actions[choice]
        data = header.to_bytes(1) + struct.pack("!I", amount)
        data = [ format(i, '08b') for i in data ]
        Packet.write_packet(self._socket, data, self._client_key,
                            self._client_IV, self._client_hmac)

    def say_goodbye(self, choice):
        _, header = self._actions[choice]
        data = [format(i, '08b') for i in header.to_bytes(1) ]
        Packet.write_packet(self._socket, data, self._client_key,
                            self._client_IV, self._client_hmac)
        self.disconnect()




    def disconnect(self):
        if self._socket is None: return
        self._socket.close()
