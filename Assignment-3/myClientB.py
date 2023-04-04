import hashlib
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


def isMessageForMe(myID, messageID):
    return myID == messageID


def SanityCheck(myID, otherID):
    print("Sanity check to confirm server has correct public key of client")
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, CLIENT_B_PORT))
    serverSocket.connect((HOST, SERVER_PORT))

    print("-" * 50)
    print("Requesting public key of client with ID: {}".format(otherID))
    # myID|otherID|currentTime|duration|nonce
    nonce = secrets.token_hex()
    request = myID + "|" + otherID + "|" + str(time.time()) + "|" + "900" + "|" + nonce
    print("(Sanity check for ClientB) Sent: {}".format(request))
    print("-" * 50)

    serverSocket.sendall(request.encode())

    response = serverSocket.recv(2048).decode()

    serverSocket.close()

    print("(Sanity check for ClientB) Received: {}".format(response))
    responsePlaintext = "|".join(response.split("|")[:-1])
    responseDigitalSignature = response.split("|")[-1]

    # ID check
    msgID = response.split("|")[2]
    if isMessageForMe(CLIENT_B_ID, msgID):
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
    responseNonce = response.split("|")[6]
    print("Nonce sent: {}".format(nonce))
    print("Nonce received: {}".format(responseNonce))
    if nonce == responseNonce:
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
    serverSocket.bind((HOST, CLIENT_B_PORT))
    serverSocket.connect((HOST, SERVER_PORT))

    print("-" * 50)
    print("Requesting public key of client with ID: {}".format(otherID))
    # myID|otherID|currentTime|duration|nonce
    nonce = secrets.token_hex()
    request = myID + "|" + otherID + "|" + str(time.time()) + "|" + "900" + "|" + nonce
    print("(4) Sent: {}".format(request))
    print("-" * 50)

    serverSocket.sendall(request.encode())

    response = serverSocket.recv(2048).decode()

    serverSocket.close()

    print("(5) Received: {}".format(response))
    responsePlaintext = "|".join(response.split("|")[:-1])
    responseDigitalSignature = response.split("|")[-1]

    # ID check
    msgID = response.split("|")[2]
    if isMessageForMe(CLIENT_B_ID, msgID):
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
    responseNonce = response.split("|")[6]
    print("Nonce sent: {}".format(nonce))
    print("Nonce received: {}".format(responseNonce))
    if nonce == responseNonce:
        print("Nonce check passed")
    else:
        print("Nonce check failed")
        exit(0)

    obtainedPublicKey = (int(responsePlaintext.split("|")[0]), int(responsePlaintext.split("|")[1]))
    print("Public key obtained: {}".format(obtainedPublicKey))
    print("-" * 50)

    return obtainedPublicKey


def RunClient():
    myPublicKey = SanityCheck(CLIENT_B_ID, CLIENT_B_ID)
    if myPublicKey == CLIENT_B_PUBLIC_KEY:
        print("Sanity check complete - server has correct public key of ClientB")
    else:
        print("Sanity check failed")
        exit(0)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.bind((HOST, CLIENT_B_PORT))
    clientSocket.listen(5)

    while True:
        otherClientSocket, addr = clientSocket.accept()
        EncryptedMsg1 = otherClientSocket.recv(2048).decode()
        msg1 = myRSA.Decrypt(EncryptedMsg1, CLIENT_B_PRIVATE_KEY)
        N1 = msg1.split("|")[-1]
        print("-" * 50)
        print("(3) Received: {}".format(msg1))
        # ID check
        if isMessageForMe(CLIENT_B_ID, msg1.split("|")[1]):
            print("ID verified")
        else:
            print("ID not verified")
            exit(0)
        # Duration check
        msg1Time = msg1.split("|")[2]
        msg1Duration = msg1.split("|")[3]
        currentTime = time.time()
        print("Time message was sent: {}".format(msg1Time))
        print("Duration of validity: {}".format(msg1Duration))
        print("Current Time: {}".format(currentTime))
        if float(msg1Time) + float(msg1Duration) >= currentTime:
            print("Duration check passed")
        else:
            print("Duration check failed")
            exit(0)

        otherClientPublicKey = GetPublicKeyByID(CLIENT_B_ID, CLIENT_A_ID)

        N2 = secrets.token_hex()
        msg2 = CLIENT_B_ID + "|" + CLIENT_A_ID + "|" + str(time.time()) + "|" + "900" + "|" + N1 + "|" + N2
        print("(6) Sent: {}".format(msg2))
        print("-" * 50)
        encryptedMsg2 = myRSA.Encrypt(msg2, otherClientPublicKey)
        otherClientSocket.sendall(encryptedMsg2.encode())

        encryptedMsg3 = otherClientSocket.recv(2048).decode()
        msg3 = myRSA.Decrypt(encryptedMsg3, CLIENT_B_PRIVATE_KEY)
        print("(7) Received: {}".format(msg3))

        # ID check
        if isMessageForMe(CLIENT_B_ID, msg3.split("|")[1]):
            print("ID verified")
        else:
            print("ID not verified")
            exit(0)

        # Duration check
        msg3Time = msg3.split("|")[2]
        msg3Duration = msg3.split("|")[3]
        currentTime = time.time()
        print("Time message was sent: {}".format(msg3Time))
        print("Duration of validity: {}".format(msg3Duration))
        print("Current Time: {}".format(currentTime))
        if float(msg3Time) + float(msg3Duration) >= currentTime:
            print("Duration check passed")
        else:
            print("Duration check failed")
            exit(0)

        # Nonce check
        responseN2 = msg3.split("|")[-1]
        print("Nonce sent: {}".format(N2))
        print("Nonce received: {}".format(responseN2))
        if N2 == responseN2:
            print("Nonce check passed")
        else:
            print("Nonce check failed")
            exit(0)

        print("-" * 50)

        # Normal conversation
        for _ in range(3):
            encryptedConvMsg = otherClientSocket.recv(2048).decode()
            convMsg = myRSA.Decrypt(encryptedConvMsg, CLIENT_B_PRIVATE_KEY)
            print("Received message from other client: {}".format(convMsg))
            convReply = input("Enter message to send: ")
            print("Sending message to other client: {}".format(convReply))
            encryptedConvReply = myRSA.Encrypt(convReply, otherClientPublicKey)
            otherClientSocket.sendall(encryptedConvReply.encode())

        otherClientSocket.close()


if __name__ == "__main__":
    RunClient()
