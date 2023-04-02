import socket
import myRSA
import time
import secrets


CLIENT_A_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
CLIENT_B_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"

SERVER_PUBLIC_KEY = (3361, 20989)

CLIENT_B_PRIVATE_KEY = (4987, 12827)
CLIENT_B_PUBLIC_KEY = (523, 12827)

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


def RunClient():
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.bind((HOST, CLIENT_B_PORT))
    clientSocket.listen(5)

    while True:
        otherClientSocket, addr = clientSocket.accept()
        EncryptedMsg1 = otherClientSocket.recv(2048).decode()
        msg1 = myRSA.Decrypt(EncryptedMsg1, CLIENT_B_PRIVATE_KEY)
        N1 = msg1.split("|")[1]
        print("Message received from other client: {}".format(msg1))

        otherClientPublicKey = GetPublicKeyByID(CLIENT_A_ID)

        N2 = secrets.token_hex()
        msg2 = N1 + "|" + N2
        print("Sending message to other client: {}".format(msg2))
        encryptedMsg2 = myRSA.Encrypt(msg2, otherClientPublicKey)
        otherClientSocket.sendall(encryptedMsg2.encode())

        encryptedMsg3 = otherClientSocket.recv(2048).decode()
        msg3 = myRSA.Decrypt(encryptedMsg3, CLIENT_B_PRIVATE_KEY)
        print("Message received from other client: {}".format(msg3))

        # Normal conversation
        conversationReplyList = ["Got-it1", "Got-it2", "Got-it3"]
        for convReply in conversationReplyList:
            encryptedConvMsg = otherClientSocket.recv(2048).decode()
            convMsg = myRSA.Decrypt(encryptedConvMsg, CLIENT_B_PRIVATE_KEY)
            print("Received message from other client: {}".format(convMsg))
            print("Sending message to other client: {}".format(convReply))
            encryptedConvReply = myRSA.Encrypt(convReply, otherClientPublicKey)
            otherClientSocket.sendall(encryptedConvReply.encode())

        otherClientSocket.close()


if __name__ == "__main__":
    RunClient()
