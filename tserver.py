from socket import *
serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM) 
serverSocket.bind(('', 12000))
print ("The server is ready to receive")
print(serverSocket.getsockname())
while True:
    message, clientAddress = serverSocket.recvfrom(2048) 
    print(message)
    print(message[:1])
    print(len(message))
    modifiedMessage = message.decode().upper() 
    print(clientAddress)
    serverSocket.sendto(modifiedMessage.encode(),clientAddress)
    # if True:
    #     break
serverSocket.close()