#! /usr/bin/env python
# utils.py

import binascii
from typing import TypeVar, Generator, Tuple, Union, List, Any
from cryptography.our_sha import my_sha1

def open_keyfile(path) -> List[Tuple[str, Any]]:
    with open(path) as f:
        keyfile = f.read()
        key = ''.join(keyfile.split()[3:-3])
        key = binascii.a2b_base64(key)
        params = list(parse_der(key))
    return params

# DataElement = TypeVar('DataElement', int, bytes, List['DataElement'])
def parse_der(data, offset=0) -> Generator[Tuple[str, Any], None, None]:
    while offset < len(data):
        tag = data[offset]
        offset += 1

        # Determine the length of the data
        length = data[offset]
        offset += 1
        if length & 0x80:  # Long form
            num_bytes = length & 0x7F
            length = int.from_bytes(data[offset:offset+num_bytes], byteorder='big')
            offset += num_bytes

        # Extract the value
        value = data[offset:offset+length]
        offset += length

        # Handle different types of tags
        if tag == 0x02:  # INTEGER
            yield ('INTEGER', int.from_bytes(value, byteorder='big', signed=False))
        elif tag == 0x30:  # SEQUENCE
            yield ('SEQUENCE', list(parse_der(value)))
        elif tag == 0x06: # OBJECT IDENTIFIER
            yield ('OBJECT IDENTIFIER (not parsed)', value)
        elif tag == 0x05: # NULL
            yield ('NULL', value)
        elif tag == 0x04: # OCTET STRING
            yield ('OCTET STRING', list(parse_der(value)))
        elif tag == 0x03: # BIT STRING
            yield ('BIT STRING', {'unused_bits': value[0], 'data': list(parse_der(value[1:]))})
        else:
            yield (f'UNKNOWN TAG {tag}', value)

def compute_key(K, H, X, session_id, key_size):
    key = my_sha1(K + H + X + session_id)
    key_length = len(key)
    while (key_length < key_size):
        next_key = my_sha1(K + H + key)
        key += next_key
        key_length = len(key)
    if key_length > key_size:
        key = key[0:key_size]
