from config import DEFAULT_PORT, DEFAULT_HOST

from socket import *


clientSocket= socket(AF_INET, SOCK_STREAM)
clientSocket.connect((DEFAULT_HOST,DEFAULT_PORT))
sentence = input('Input lowercase sentence:')
clientSocket.send(sentence.encode())
modifiedSentence= clientSocket.recv(1024)
print ('From Server:', modifiedSentence.decode())
clientSocket.close()