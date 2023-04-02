import socket
import myRSA
import time
import secrets


CLIENT_A_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
CLIENT_B_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"

SERVER_PUBLIC_KEY = (3361, 20989)

CLIENT_A_PRIVATE_KEY = (3947, 7387)
CLIENT_A_PUBLIC_KEY = (3459, 7387)

HOST = "127.0.0.1"
SERVER_PORT = 8000
CLIENT_A_PORT = 6000
CLIENT_B_PORT = 7000


def GetPublicKeyByID(ID):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, CLIENT_A_PORT))
    print("Requesting public key of client with ID: {}".format(ID))
    serverSocket.connect((HOST, SERVER_PORT))
    request = ID + "|" + str(time.time()) + "|" + "900" + "|" + secrets.token_hex()
    serverSocket.sendall(request.encode())
    response = serverSocket.recv(2048).decode()
    serverSocket.close()
    decryptedResponse = myRSA.Decrypt(response, SERVER_PUBLIC_KEY)
    print("Response obtained: {}".format(decryptedResponse))
    obtainedPublicKey = (int(decryptedResponse.split("|")[0]), int(decryptedResponse.split("|")[1]))
    print("Public key obtained: {}".format(obtainedPublicKey))

    return obtainedPublicKey


def InitiateConversation(otherClientPublicKey, port):
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.connect((HOST, port))

    msg1 = CLIENT_A_ID + "|" + secrets.token_hex()
    print("Sending message to other client: {}".format(msg1))
    encryptedMsg1 = myRSA.Encrypt(msg1, otherClientPublicKey)
    clientSocket.sendall(encryptedMsg1.encode())

    encryptedMsg2 = clientSocket.recv(2048).decode()
    msg2 = myRSA.Decrypt(encryptedMsg2, CLIENT_A_PRIVATE_KEY)
    print("Message received from other client: {}".format(msg2))

    N2 = msg2.split("|")[1]
    msg3 = N2
    encryptedMsg3 = myRSA.Encrypt(msg3, otherClientPublicKey)
    clientSocket.sendall(encryptedMsg3.encode())

    # Normal conversation
    conversationList = ["Hi1", "Hi2", "Hi3"]
    for conv in conversationList:
        print("Sending message to other client: {}".format(conv))
        encryptedConv = myRSA.Encrypt(conv, otherClientPublicKey)
        clientSocket.sendall(encryptedConv.encode())
        encryptedConvReply = clientSocket.recv(2048).decode()
        ConvReply = myRSA.Decrypt(encryptedConvReply, CLIENT_A_PRIVATE_KEY)
        print("Received message from other client: {}".format(ConvReply))

    clientSocket.close()


def RunClient():
    otherClientPublicKey = GetPublicKeyByID(CLIENT_B_ID)
    InitiateConversation(otherClientPublicKey, CLIENT_B_PORT)


if __name__ == "__main__":
    RunClient()
