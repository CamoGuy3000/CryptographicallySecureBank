#! /usr/bin/env python

from ssh.server import SSHServer

if __name__ == "__main__":
    server = SSHServer()
    print(server._host)
    print(server._port)
    server.listen()
    server.poll()
    server.stop()
