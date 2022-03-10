# Project 1 - Sockets
# Author - Timur Guner
# Class - CS372 Winter 2022

# This has been adapted from the book as well as using https://www.youtube.com/watch?v=8DvywoWv6fI sockets

import socket

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creates the tcp socket
serverSocket.bind(('127.0.0.1', 8000)) # binds the created socket the the host and port
serverSocket.listen(1) # this line has the server listen
print("Connect by ('127.0.0.1',8000)\n") # lets us know the server is running


connectionSocket, add = serverSocket.accept() # the accept method creates creates a new socket called connectionSocket and
sentence = connectionSocket.recv(1024) # get the response
print('Received:',sentence) # print it to the console in the encoded format

response = "HTTP/1.1 200 OK\r\n" \
       "Content-Type: text/html; charset=UTF-8\r\n\r\n" \
       "<html>Congratulations!  You've downloaded the first Wireshark lab file!</html>\r\n" # the response we will send to the user
print('\nSending >>>>>>>>>') # the next three lines print the response the server is sending to the console
print(response)
print('<<<<<<<<<')

connectionSocket.send(response.encode()) # send the response encoded to display as html to the user
connectionSocket.close() # close the socket
