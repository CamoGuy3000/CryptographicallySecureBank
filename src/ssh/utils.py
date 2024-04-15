#! /usr/bin/env python
# utils.py

import binascii
from typing import TypeVar, Generator, Tuple, Union, List, Any

def open_keyfile(path):
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
        elif tag == 0x05: # OBJECT IDENTIFIER
            yield ('NULL', value)
        elif tag == 0x04: # OBJECT IDENTIFIER
            yield ('OCTET STRING', list(parse_der(value)))
        else:
            yield (f'UNKNOWN TAG {tag}', value)
