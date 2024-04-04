

import socket
import keyboard

state = True

def stop():
  global state
  state = False

keyboard.add_hotkey('esc', stop)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         name              port# 
s.bind((socket.gethostname(), 6463))
#       max connection
s.listen(5)

while state:
  clientSocket, address = s.accept()
  print(f"Connection established from address {address}")
  clientSocket.send(bytes("Welcome to the server! Please enter username", "utf-8"))
  user = clientSocket.recv(2048)
  clientSocket.send(bytes("Please enter password", "utf-8"))
  passw = clientSocket.recv(2048)
  clientSocket.close()
  print("Received username:", str(user), "\nWith password:", str(passw))

