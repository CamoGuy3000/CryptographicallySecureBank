#! /usr/bin/env python
# server.py

import socket
import random
import time
import sqlite3
import struct
from ssh.utils import open_keyfile, compute_key
from cryptography.our_rsa import rsa_encrypt, rsa_decrypt, rsa_verify
from ssh.kex import KEX
from ssh.packet import Packet
from cryptography.our_sha import my_sha1

class SSHServer:
    # what it sounds like.

    def __init__(self, port=12345):
        self._socket = None
        self._host = socket.gethostbyname(socket.gethostname())
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
            "3": ("Withdraw", 3)
        }
        self.connection = sqlite3.connect("sqlite_file")
        self.cursor = self.connection.cursor()
        self.setup_database()

    def listen(self):
        self.stop()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((self._host, self._port))
        self._socket.listen(0)
        print(f"Bank open at {self._host} on port {self._port}.")

    def poll(self):
        if self._socket is None: return
        conn, addr = self._socket.accept()
        with conn:
            print(f"Connected by {addr}")

            # ephemeral diffie hellman
            client_dh = int.from_bytes(conn.recv(256), byteorder='big')
            # print(f"Client public DH: {client_dh}")
            public_dh = KEX.create_key()
            # print(f"My public DH: {public_dh}")
            conn.sendall(public_dh.to_bytes(256, byteorder='big'))
            shared_secret = KEX.shared_secret(client_dh)
            # print(f"Shared secret: {shared_secret}")

            # send host public key for verification
            public_key_params = open_keyfile("../keys/bank.pub")[0][1][1][1]
            if public_key_params['unused_bits'] != 0:
                raise ValueError("Cannot handle unused bits :(")
            n = public_key_params['data'][0][1][0][1]
            e = public_key_params['data'][0][1][1][1] # 65537
            
            # print(f"Bank Modulus: {n}")
            # print(f"Bank Exponent: {e}")
            conn.sendall(n.to_bytes(129))
            conn.sendall(e.to_bytes(3))

            # compute session hash
            client_cookie = conn.recv(256)
            cookie = random.getrandbits(16).to_bytes(2)
            conn.sendall(cookie)
            # print(f"Cookies:")
            # print(f"\tClient: {client_cookie}")
            # print(f"\tServer: {cookie}")
            client_payload = KEX.compute_kexinit_payload(client_cookie)
            server_payload = KEX.compute_kexinit_payload(cookie)
            hash_list = [ KEX.version_string*2, client_payload, server_payload,
                          e.to_bytes(3), n.to_bytes(129),
                          client_dh.to_bytes(256), public_dh.to_bytes(256),
                          shared_secret.to_bytes((shared_secret.bit_length()+7)//8)]
            session_hash = my_sha1(b''.join(hash_list))
            # print(f"Session hash: {session_hash}")

            # read private key to authenticate server to client
            private_key_params = open_keyfile("../keys/bank")[0][1][2]
            private_exp = private_key_params[1][0][1][3][1]
            private_mod = private_key_params[1][0][1][1][1]
            rsa_enc = list(bytes(session_hash, 'utf-8'))
            print(f"session hash - {session_hash}")
            re, ctxt, hashed = rsa_encrypt(list(bytes(session_hash, 'utf-8')),
                                        private_mod, private_exp)
            re_bytes = re.to_bytes((re.bit_length() + 7) // 8, 'big')
            ctxt_bytes = b''.join([int(b, 2).to_bytes((len(b) + 7) // 8, 'big') for b in ctxt])
            hashed_bytes = bytes.fromhex(hashed)
            message = len(re_bytes).to_bytes(2, 'big') + re_bytes + \
                      len(ctxt_bytes).to_bytes(2, 'big') + ctxt_bytes + \
                      len(hashed_bytes).to_bytes(2, 'big') + hashed_bytes
            conn.sendall(message)
            # print(f"Sent\n\tre:{re}\n\tctxt: {ctxt_bytes}\n\thash: {hashed}")


            # ATM authentication
            # recv public key as bytes
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

            # issue challenge
            cur_time = int(time.time())
            challenge_list = [ random.getrandbits(16).to_bytes(2),
                               atm_e.to_bytes(3), atm_n.to_bytes(129), 
                               cur_time.to_bytes((cur_time.bit_length()+7)//8) ]
            challenge = b''.join(challenge_list)
            conn.sendall(challenge)
            challenge = my_sha1(session_hash.encode() + challenge)

            # read response
            re_length = int.from_bytes(conn.recv(2))
            re = int.from_bytes(conn.recv(re_length))
            ctxt_length = int.from_bytes(conn.recv(2))
            ctxt_bytes = conn.recv(ctxt_length)
            hashed_length = int.from_bytes(conn.recv(2))
            hashed = conn.recv(hashed_length).hex()
            r, ptxt = rsa_decrypt((re, ctxt_bytes, hashed), atm_n, 1, atm_e)
            ptxt = b''.join([ int(x, 2).to_bytes() for x in ptxt ]).decode()
            if not rsa_verify(ctxt_bytes, r, hashed):
                print(f"Hash does not match match :((")
                self.stop()

            # Check if the user account exists, if not, create one
            username = 1
            # I don't want to bother writing a funny check into known clients
            # or something so everyone is user 1
            if not self.cursor.execute("SELECT id FROM accounts WHERE id = 1").fetchone():
                self.cursor.execute("INSERT INTO accounts (id, balance) VALUES (1, 1000)")
                self.connection.commit()


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
            while (1):
                data = Packet.read_packet(conn, self._client_key,
                                            self._client_IV, self._client_hmac)
                print(f"data: {data}")
                if data[0] == 1:
                    balance = self.get_balance()
                    to_send = struct.pack("!I", balance)
                    to_send = [ format(i, '08b') for i in to_send ]
                    Packet.write_packet(conn, to_send, self._server_key,
                                        self._server_IV, self._server_hmac)
                elif data[0] == 2:
                    amount = struct.unpack("!I", data[1:5])[0]
                    self.deposit(amount)
                elif data[0] == 3:
                    amount = struct.unpack("!I", data[1:5])[0]
                    self.withdraw(amount)
                elif data[0] == 4:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    break

    def setup_database(self):
        """Create the database table if it doesn't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0
            );
        """)
        self.connection.commit()

    def deposit(self, amount):
        """Deposit money to the account."""
        self.cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = 1", (amount,))
        self.connection.commit()
        print(f"Deposited ${amount}. New balance is ${self.get_balance()}.")

    def withdraw(self, amount):
        """Withdraw money from the account."""
        current_balance = self.get_balance()
        if amount > current_balance:
            print("Insufficient funds.")
        else:
            self.cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = 1", (amount,))
            self.connection.commit()
            print(f"Withdrew ${amount}. New balance is ${self.get_balance()}.")

    def get_balance(self):
        """Retrieve the current balance from the database."""
        self.cursor.execute("SELECT balance FROM accounts WHERE id = 1")
        return self.cursor.fetchone()[0]

    def close(self):
        """Close the database connection."""
        self.connection.close()

    def stop(self):
        if self._socket is None: return
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
