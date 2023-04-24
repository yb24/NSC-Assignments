import socket
import hashlib
import secrets
import os
import pypdf
import io
from datetime import datetime
from Helper import myRSA, myTime, myOTP


NTP_SERVER_IP = "in.pool.ntp.org"

CLIENT_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
PKDA_ID = "6c01891b-02cd-427b-af45-0f144a299780"
SERVER_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"
REGISTRAR_ID = "d3f33961-e7e9-4bd3-9d04-c9950ca84db6"
DIRECTOR_ID = "0894eb8f-8362-409b-a696-619f1f3842e9"

PKDA_PUBLIC_KEY = (3361, 20989)
PKDA_PORT = 9100
CLIENT_PORT = 9000

MY_PRIVATE_KEY = (4987, 12827)
MY_PUBLIC_KEY = (523, 12827)
HOST = "127.0.0.1"
MY_PORT = 9200

CLIENT_PERSONAL_DETAILS = {
    '2019289': ('Yash Bhargava', 'yash19289@iiitd.ac.in', '2000-12-24')
}


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
        print("Digital signature from PKDA verified")
    else:
        print("Digital signature from PKDA invalid")
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


def VerifyPersonalDetails(name, email, rollNo, DOB):
    if CLIENT_PERSONAL_DETAILS[rollNo][0] == name:
        print("Name verified")
    else:
        print("Name not verified")
        exit(0)

    if CLIENT_PERSONAL_DETAILS[rollNo][1] == email:
        print("Email verified")
    else:
        print("Email not verified")
        exit(0)

    if CLIENT_PERSONAL_DETAILS[rollNo][2] == DOB:
        print("DOB verified")
    else:
        print("DOB not verified")
        exit(0)


def VerifyOTP(sentOTP, receivedOTP, timeOfSending, validOTPDuration):
    if sentOTP == receivedOTP:
        print("OTP matched")
    else:
        print("OTP not matched")
        exit(0)
    VerifyDuration(timeOfSending, validOTPDuration)


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


def DigitalSignatureByRegistrar(plaintext):
    REGISTRAR_PRIVATE_KEY = (2563, 12091)
    hashOfPlaintext = hashlib.sha256(plaintext.encode()).hexdigest()
    digitalSignature = myRSA.Encrypt(hashOfPlaintext, REGISTRAR_PRIVATE_KEY)
    signedDocument = plaintext + "|" + digitalSignature

    return signedDocument


def DigitalSignatureByDirector(plaintext):
    DIRECTOR_PRIVATE_KEY = (1253, 14279)
    hashOfPlaintext = hashlib.sha256(plaintext.encode()).hexdigest()
    digitalSignature = myRSA.Encrypt(hashOfPlaintext, DIRECTOR_PRIVATE_KEY)
    signedDocument = plaintext + "|" + digitalSignature

    return signedDocument


def SendDocument(client, docPath, watermarkPath):
    with open(docPath, "rb") as input_file, open(watermarkPath, "rb") as watermark_file:
        input_pdf = pypdf.PdfReader(input_file)
        watermark_pdf = pypdf.PdfReader(watermark_file)
        pdf_writer = pypdf.PdfWriter()

        watermark_page = watermark_pdf.pages[0]

        for pg_no in range(len(input_pdf.pages)):
            page = input_pdf.pages[pg_no]
            page2 = watermark_page
            page2.merge_page(page)
            pdf_writer.add_page(page2)

        pdf_bytes_io = io.BytesIO()
        pdf_writer.write(pdf_bytes_io)
        pdf_byte_string = pdf_bytes_io.getvalue()

    pdf_string = pdf_byte_string.decode("latin-1")

    # Add current date and time
    dateAndTime = myTime.GetCurrentTime(NTP_SERVER_IP)
    currentDateAndTime = datetime.fromtimestamp(dateAndTime).strftime("%a %b %d %Y %H:%M:%S.%f")
    document = pdf_string + "|" + currentDateAndTime

    # Get document signed by Registrar
    documentSignedByRegistrar = DigitalSignatureByRegistrar(document)

    # Get document signed by Director
    documentSignedByBoth = DigitalSignatureByDirector(documentSignedByRegistrar)

    client.sendall(documentSignedByBoth.encode("latin-1"))


def RunServer():
    SanityCheck(SERVER_ID)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    clientSocket.bind((HOST, MY_PORT))
    clientSocket.listen(5)

    while True:
        otherClientSocket, addr = clientSocket.accept()

        myID = SERVER_ID
        otherID = CLIENT_ID

        # Receiving request for degree / grade card
        EncryptedMsg1 = otherClientSocket.recv(2048).decode("latin-1")
        msg1 = myRSA.Decrypt(EncryptedMsg1, MY_PRIVATE_KEY)

        print("-" * 50)
        print("Received: {}".format(msg1))

        # ID check
        isMessageForMe(myID, msg1.split("|")[1])
        # Personal details check
        clientName, clientEmail, clientRollNo, clientDOB = msg1.split("|")[2], msg1.split("|")[3], msg1.split("|")[4], msg1.split("|")[5]
        VerifyPersonalDetails(clientName, clientEmail, clientRollNo, clientDOB)
        # Duration verification
        VerifyDuration(msg1.split("|")[6], msg1.split("|")[7])
        # Nonce N1
        N1 = msg1.split("|")[8]

        # Get public key of client
        otherClientPublicKey = GetPublicKeyByID(myID, otherID)

        # Send OTP for verification
        OTP, timeOTPWasSent = myOTP.generateAndSendOTP(msg1.split("|")[3], NTP_SERVER_IP)
        N2 = secrets.token_hex()
        msg2 = "|".join([
            myID,
            otherID,
            "Enter OTP within 300 seconds for verification",
            str(myTime.GetCurrentTime(NTP_SERVER_IP)),
            "900",
            N1,
            N2
        ])
        EncryptedMsg2 = myRSA.Encrypt(msg2, otherClientPublicKey)
        otherClientSocket.sendall(EncryptedMsg2.encode("latin-1"))

        # Receive OTP response
        EncryptedMsg3 = otherClientSocket.recv(2048).decode("latin-1")
        msg3 = myRSA.Decrypt(EncryptedMsg3, MY_PRIVATE_KEY)
        print("-" * 50)
        print("Received: {}".format(msg3))
        # ID check
        isMessageForMe(myID, msg3.split("|")[1])
        # Duration verification
        VerifyDuration(msg3.split("|")[3], msg3.split("|")[4])
        # Nonce check
        VerifyNonce(N2, msg3.split("|")[5])
        # OTP verification
        VerifyOTP(msg3.split("|")[2], OTP, timeOTPWasSent, "300")

        # Send document
        docPath = os.path.join("Database", clientRollNo + ".pdf")
        watermarkPath = os.path.join("Database", "watermark.pdf")
        SendDocument(otherClientSocket, docPath, watermarkPath)

        otherClientSocket.close()


if __name__ == "__main__":
    RunServer()
