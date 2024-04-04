import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 6463))

message = s.recv(2048)
print(f"Message received: {message}")
if message != b"Welcome to the server! Please enter username":
  print("Unexpected Token. Exiting")
  exit(1)
user = input("Input your username:\n>")
s.send(bytes(user, "utf-8"))
message = s.recv(2048)
if message != b"Please enter password":
  print("Unexpected Token. Exiting")
  exit(1)
passw = input("Input your password:\n>")
s.send(bytes(passw, "utf-8"))
s.close()