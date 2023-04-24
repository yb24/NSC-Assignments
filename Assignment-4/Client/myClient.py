import os
import socket
import hashlib
import secrets
from Helper import myRSA, myTime


NTP_SERVER_IP = "in.pool.ntp.org"

CLIENT_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
PKDA_ID = "6c01891b-02cd-427b-af45-0f144a299780"
SERVER_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"
REGISTRAR_ID = "d3f33961-e7e9-4bd3-9d04-c9950ca84db6"
DIRECTOR_ID = "0894eb8f-8362-409b-a696-619f1f3842e9"

PKDA_PUBLIC_KEY = (3361, 20989)
PKDA_PORT = 9100
SERVER_PORT = 9200

MY_PRIVATE_KEY = (3947, 7387)
MY_PUBLIC_KEY = (3459, 7387)
HOST = "127.0.0.1"
MY_PORT = 9000


def isMessageForMe(myID, messageID):
    if myID == messageID:
        print("ID verified")
    else:
        print("ID not verified")
        exit(0)


def VerifyDigitalSignature(plaintext, digitalSignature, key):
    decryptedDigitalSignature = myRSA.Decrypt(digitalSignature, key)
    hashOfPlaintext = hashlib.sha256(plaintext.encode()).hexdigest()

    print("Decrypted digital signature: {}".format(decryptedDigitalSignature))
    print("Hash of plaintext: {}".format(hashOfPlaintext))

    if decryptedDigitalSignature == hashOfPlaintext:
        print("Digital signature verified")
    else:
        print("Digital signature invalid")
        exit(0)


def VerifyDuration(msgTime, validityDuration):
    currentTime = myTime.GetCurrentTime(NTP_SERVER_IP)

    print("Time message was sent: {}".format(msgTime))
    print("Duration of validity: {}".format(validityDuration))
    print("Current Time: {}".format(currentTime))

    if float(msgTime) + float(validityDuration) >= currentTime:
        print("Duration check passed")
    else:
        print("Duration check failed")
        exit(0)


def VerifyNonce(nonceA, nonceB):
    print("Nonce sent: {}".format(nonceA))
    print("Nonce received: {}".format(nonceB))
    if nonceA == nonceB:
        print("Nonce check passed")
    else:
        print("Nonce check failed")
        exit(0)


def GetPublicKeyByID(myID, otherID):
    PKDASocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    PKDASocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    PKDASocket.bind((HOST, MY_PORT))
    PKDASocket.connect((HOST, PKDA_PORT))

    print("-" * 50)
    print("Requesting public key of ID: {}".format(otherID))
    # myID|otherID|currentTime|duration|nonce
    nonce = secrets.token_hex()
    request = myID + "|" + otherID + "|" + str(myTime.GetCurrentTime(NTP_SERVER_IP)) + "|" + "900" + "|" + nonce
    print("Sent: {}".format(request))
    print("-" * 50)

    PKDASocket.sendall(request.encode("latin-1"))

    response = PKDASocket.recv(2048).decode("latin-1")

    PKDASocket.close()

    print("Received: {}".format(response))
    responsePlaintext = "|".join(response.split("|")[:-1])
    responseDigitalSignature = response.split("|")[-1]

    # ID check
    msgID = response.split("|")[2]
    isMessageForMe(myID, msgID)

    # Digital Signature Verification
    VerifyDigitalSignature(responsePlaintext, responseDigitalSignature, PKDA_PUBLIC_KEY)

    # Duration verification
    responseTime = response.split("|")[4]
    responseDuration = response.split("|")[5]
    VerifyDuration(responseTime, responseDuration)

    # Nonce check
    responseNonce = response.split("|")[6]
    VerifyNonce(nonce, responseNonce)

    obtainedPublicKey = (int(responsePlaintext.split("|")[0]), int(responsePlaintext.split("|")[1]))
    print("Public key obtained: {}".format(obtainedPublicKey))
    print("-" * 50)

    return obtainedPublicKey


def SanityCheck(myID):
    myPublicKey = GetPublicKeyByID(myID, myID)
    if myPublicKey == MY_PUBLIC_KEY:
        print("Sanity check complete - PKDA has my correct public key")
    else:
        print("Sanity check failed")
        exit(0)


def GetDegreeGradeCard(otherPublicKey, registrarPublicKey, directorPublicKey, port):
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.connect((HOST, port))

    myID = CLIENT_ID
    otherID = SERVER_ID

    # Request for degree / grade card
    myName = input("Enter your name: ")
    myEmail = input("Enter your email: ")
    myRollNo = input("Enter your roll no: ")
    myDOB = input("Enter your DOB in format yyyy-mm-dd: ")

    N1 = secrets.token_hex()
    msg1 = "|".join([
        myID,
        otherID,
        myName,
        myEmail,
        myRollNo,
        myDOB,
        str(myTime.GetCurrentTime(NTP_SERVER_IP)),
        "900",
        N1
    ])
    encryptedMsg1 = myRSA.Encrypt(msg1, otherPublicKey)
    clientSocket.sendall(encryptedMsg1.encode("latin-1"))

    EncryptedMsg2 = clientSocket.recv(2048).decode("latin-1")
    msg2 = myRSA.Decrypt(EncryptedMsg2, MY_PRIVATE_KEY)
    print("-" * 50)
    print("Received: {}".format(msg2))
    # ID check
    isMessageForMe(myID, msg2.split("|")[1])
    # Duration verification
    VerifyDuration(msg2.split("|")[3], msg2.split("|")[4])
    # Nonce check
    VerifyNonce(N1, msg2.split("|")[5])
    # Nonce N2
    N2 = msg2.split("|")[6]
    # Print message from server
    print(msg2.split("|")[2])

    # Send OTP for verification
    OTP = input("Enter OTP received on email: ")
    msg3 = "|".join([
        myID,
        otherID,
        OTP,
        str(myTime.GetCurrentTime(NTP_SERVER_IP)),
        "900",
        N2
    ])
    EncryptedMsg3 = myRSA.Encrypt(msg3, otherPublicKey)
    clientSocket.sendall(EncryptedMsg3.encode("latin-1"))

    # Receive document
    response = ""
    while True:
        chunk = clientSocket.recv(1024).decode("latin-1")
        if not chunk:
            break
        response += chunk

    # Director digital signature verification
    plaintext2 = "|".join(response.split("|")[:-1])
    digitalSignature2 = response.split("|")[-1]
    VerifyDigitalSignature(plaintext2, digitalSignature2, directorPublicKey)

    # Registrar digital signature verification
    plaintext1 = "|".join(plaintext2.split("|")[:-1])
    digitalSignature1 = plaintext2.split("|")[-1]
    VerifyDigitalSignature(plaintext1, digitalSignature1, registrarPublicKey)

    dateAndTimeOnDocument = plaintext1.split("|")[-1]
    print("Date and time on document: {}".format(dateAndTimeOnDocument))

    pdf_data = response.encode("latin-1")
    outputDocPath = os.path.join(myName + " " + myRollNo + ".pdf")
    with open(outputDocPath, "wb") as file:
        file.write(pdf_data)

    clientSocket.close()


def RunClient():
    SanityCheck(CLIENT_ID)
    serverPublicKey = GetPublicKeyByID(CLIENT_ID, SERVER_ID)
    registrarPublicKey = GetPublicKeyByID(CLIENT_ID, REGISTRAR_ID)
    directorPublicKey = GetPublicKeyByID(CLIENT_ID, DIRECTOR_ID)
    GetDegreeGradeCard(serverPublicKey, registrarPublicKey, directorPublicKey, SERVER_PORT)


if __name__ == "__main__":
    RunClient()
