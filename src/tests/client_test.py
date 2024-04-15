#! /usr/bin/env python

from ssh import client

if __name__ == "__main__":
    client = client.SSHClient(port=12345)
    print(client._host)
    print(client._port)
    client.connect()
