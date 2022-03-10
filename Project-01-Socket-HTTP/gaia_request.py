import socket

mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creates the socket
mysock.connect(('gaia.cs.umass.edu', 80)) # tcp connection is established

cmdsmall = 'GET /wireshark-labs/INTRO-wireshark-file1.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n'.encode() # the URI with GET to encode and send for a response
#mysock.send(cmdsmall) # the socket sends the get request over

cmdlarge = 'GET /wireshark-labs/HTTP-wireshark-file3.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n'.encode() # the URI with GET to encode and send for a responsefor larger response
mysock.send(cmdlarge) # the socket sends the get request over

while True:
    data = mysock.recv(2048) # receive 2048 bytes of data at a time
    if len(data) < 1: # if no data is read, then break out of loop
        break
    print(data.decode(),end='') # print the decoded message back to us
mysock.close() # close the socket once the while loop is broken