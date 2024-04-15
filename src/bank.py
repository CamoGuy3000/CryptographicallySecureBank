#! /usr/bin/env python

from ssh.server import SSHServer

if __name__ == "__main__":
    server = SSHServer()
    server.listen()
    while (1):
        server.poll()
    server.stop()
