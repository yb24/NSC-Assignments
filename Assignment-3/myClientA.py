import hashlib
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


def isMessageForMe(myID, messageID):
    return myID == messageID


def SanityCheck(myID, otherID):
    print("Sanity check to confirm server has correct public key of client")
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, CLIENT_A_PORT))
    serverSocket.connect((HOST, SERVER_PORT))

    print("-" * 50)
    print("Requesting public key of client with ID: {}".format(otherID))
    # myID|otherID|currentTime|duration|nonce
    nonce = secrets.token_hex()
    request = myID + "|" + otherID + "|" + str(time.time()) + "|" + "900" + "|" + nonce
    print("(Sanity check for ClientA) Sent: {}".format(request))
    print("-" * 50)

    serverSocket.sendall(request.encode())

    response = serverSocket.recv(2048).decode()

    serverSocket.close()

    print("(Sanity check for ClientA) Received: {}".format(response))
    responsePlaintext = "|".join(response.split("|")[:-1])
    responseDigitalSignature = response.split("|")[-1]

    # ID check
    msgID = response.split("|")[2]
    if isMessageForMe(CLIENT_A_ID, msgID):
        print("ID verified")
    else:
        print("ID not verified")
        exit(0)

    # Digital Signature Verification
    decryptedDigitalSignature = myRSA.Decrypt(responseDigitalSignature, SERVER_PUBLIC_KEY)
    hashOfPlaintext = hashlib.sha256(responsePlaintext.encode()).hexdigest()
    print("Decrypted digital signature: {}".format(decryptedDigitalSignature))
    print("Hash of plaintext: {}".format(hashOfPlaintext))
    if decryptedDigitalSignature == hashOfPlaintext:
        print("Digital signature from server verified")
    else:
        print("Digital signature from server invalid")
        exit(0)

    # Duration verification
    responseTime = response.split("|")[4]
    responseDuration = response.split("|")[5]
    currentTime = time.time()
    print("Time message was sent: {}".format(responseTime))
    print("Duration of validity: {}".format(responseDuration))
    print("Current Time: {}".format(currentTime))
    if float(responseTime) + float(responseDuration) >= currentTime:
        print("Duration check passed")
    else:
        print("Duration check failed")
        exit(0)

    # Nonce check
    responseNone = response.split("|")[6]
    print("Nonce sent: {}".format(nonce))
    print("Nonce received: {}".format(responseNone))
    if nonce == responseNone:
        print("Nonce check passed")
    else:
        print("Nonce check failed")
        exit(0)

    obtainedPublicKey = (int(responsePlaintext.split("|")[0]), int(responsePlaintext.split("|")[1]))
    print("Public key obtained: {}".format(obtainedPublicKey))
    print("-" * 50)

    return obtainedPublicKey


def GetPublicKeyByID(myID, otherID):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, CLIENT_A_PORT))
    serverSocket.connect((HOST, SERVER_PORT))

    print("-" * 50)
    print("Requesting public key of client with ID: {}".format(otherID))
    # myID|otherID|currentTime|duration|nonce
    nonce = secrets.token_hex()
    request = myID + "|" + otherID + "|" + str(time.time()) + "|" + "900" + "|" + nonce
    print("(1) Sent: {}".format(request))
    print("-" * 50)

    serverSocket.sendall(request.encode())

    response = serverSocket.recv(2048).decode()

    serverSocket.close()

    print("(2) Received: {}".format(response))
    responsePlaintext = "|".join(response.split("|")[:-1])
    responseDigitalSignature = response.split("|")[-1]

    # ID check
    msgID = response.split("|")[2]
    if isMessageForMe(CLIENT_A_ID, msgID):
        print("ID verified")
    else:
        print("ID not verified")
        exit(0)

    # Digital Signature Verification
    decryptedDigitalSignature = myRSA.Decrypt(responseDigitalSignature, SERVER_PUBLIC_KEY)
    hashOfPlaintext = hashlib.sha256(responsePlaintext.encode()).hexdigest()
    print("Decrypted digital signature: {}".format(decryptedDigitalSignature))
    print("Hash of plaintext: {}".format(hashOfPlaintext))
    if decryptedDigitalSignature == hashOfPlaintext:
        print("Digital signature from server verified")
    else:
        print("Digital signature from server invalid")
        exit(0)

    # Duration verification
    responseTime = response.split("|")[4]
    responseDuration = response.split("|")[5]
    currentTime = time.time()
    print("Time message was sent: {}".format(responseTime))
    print("Duration of validity: {}".format(responseDuration))
    print("Current Time: {}".format(currentTime))
    if float(responseTime) + float(responseDuration) >= currentTime:
        print("Duration check passed")
    else:
        print("Duration check failed")
        exit(0)

    # Nonce check
    responseNone = response.split("|")[6]
    print("Nonce sent: {}".format(nonce))
    print("Nonce received: {}".format(responseNone))
    if nonce == responseNone:
        print("Nonce check passed")
    else:
        print("Nonce check failed")
        exit(0)

    obtainedPublicKey = (int(responsePlaintext.split("|")[0]), int(responsePlaintext.split("|")[1]))
    print("Public key obtained: {}".format(obtainedPublicKey))
    print("-" * 50)

    return obtainedPublicKey


def InitiateConversation(otherClientPublicKey, port):
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.connect((HOST, port))

    N1 = secrets.token_hex()
    msg1 = CLIENT_A_ID + "|" + CLIENT_B_ID + "|" + str(time.time()) + "|" + "900" + "|" + N1
    print("(3) Sent: {}".format(msg1))
    print("-" * 50)
    encryptedMsg1 = myRSA.Encrypt(msg1, otherClientPublicKey)
    clientSocket.sendall(encryptedMsg1.encode())

    encryptedMsg2 = clientSocket.recv(2048).decode()
    msg2 = myRSA.Decrypt(encryptedMsg2, CLIENT_A_PRIVATE_KEY)
    print("(6) Received: {}".format(msg2))

    # ID check
    if isMessageForMe(CLIENT_A_ID, msg2.split("|")[1]):
        print("ID verified")
    else:
        print("ID not verified")
        exit(0)

    # Duration check
    msg2Time = msg2.split("|")[2]
    msg2Duration = msg2.split("|")[3]
    currentTime = time.time()
    print("Time message was sent: {}".format(msg2Time))
    print("Duration of validity: {}".format(msg2Duration))
    print("Current Time: {}".format(currentTime))
    if float(msg2Time) + float(msg2Duration) >= currentTime:
        print("Duration check passed")
    else:
        print("Duration check failed")
        exit(0)

    # Nonce check
    responseN1 = msg2.split("|")[4]
    print("Nonce sent: {}".format(N1))
    print("Nonce received: {}".format(responseN1))
    if N1 == responseN1:
        print("Nonce check passed")
    else:
        print("Nonce check failed")
        exit(0)
    print("-" * 50)

    N2 = msg2.split("|")[-1]
    msg3 = CLIENT_A_ID + "|" + CLIENT_B_ID + "|" + str(time.time()) + "|" + "900" + "|" + N2
    print("(7) Sent: {}".format(msg3))
    print("-" * 50)
    encryptedMsg3 = myRSA.Encrypt(msg3, otherClientPublicKey)
    clientSocket.sendall(encryptedMsg3.encode())

    # Normal conversation
    for _ in range(3):
        conv = input("Enter message to send: ")
        print("Sending message to other client: {}".format(conv))
        encryptedConv = myRSA.Encrypt(conv, otherClientPublicKey)
        clientSocket.sendall(encryptedConv.encode())
        encryptedConvReply = clientSocket.recv(2048).decode()
        ConvReply = myRSA.Decrypt(encryptedConvReply, CLIENT_A_PRIVATE_KEY)
        print("Received message from other client: {}".format(ConvReply))

    clientSocket.close()


def RunClient():
    myPublicKey = SanityCheck(CLIENT_A_ID, CLIENT_A_ID)
    if myPublicKey == CLIENT_A_PUBLIC_KEY:
        print("Sanity check complete - server has correct public key of ClientA")
    else:
        print("Sanity check failed")
        exit(0)
    otherClientPublicKey = GetPublicKeyByID(CLIENT_A_ID, CLIENT_B_ID)
    InitiateConversation(otherClientPublicKey, CLIENT_B_PORT)


if __name__ == "__main__":
    RunClient()
