#! /usr/bin/env python

import socket

class Packet:
    """
    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length
    """
    @staticmethod
    def read_packet(sock):
        max_packet_size = 35000
        block_size = 8 # DEPENDS ON CIPHER BLOCK SIZE
        first_block = sock.recv(block_size)
        if len(first_block) < block_size:
            print("Failed to read from socket.")
            return

        # TODO : decryption

        packet_length = socket.ntohl(int.from_bytes(first_block[0:4]))
        if packet_length > max_packet_size:
            print("too big!")
            return
        padding_length = int.from_bytes(first_block[4])
        
        bytes_to_read = packet_length - (block_size - 4)
        packet_remaining = sock.recv(bytes_to_read)

        if len(packet_remaining) != bytes_to_read:
            print("failed to read")
            return

        # TODO : decryption

        payload_size = packet_length - padding_length - 1
        packet = first_block[4:] + packet_remaining
        payload = packet[:(payload_size)]

        # TODO : packet sequence (for MAC computation)

        # TODO : read MAC

        # TODO : packet object ? ?


    def __init__(self, socket):
        self._socket = socket
        self._blocksize = 8; # DEPENDS ON clienttoserver CIPHER

