import socket
import threading
import hashlib
import myRSA
import myTime


CLIENT_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
PKDA_ID = "6c01891b-02cd-427b-af45-0f144a299780"
SERVER_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"
REGISTRAR_ID = "d3f33961-e7e9-4bd3-9d04-c9950ca84db6"
DIRECTOR_ID = "0894eb8f-8362-409b-a696-619f1f3842e9"

MY_PRIVATE_KEY = (20041, 20989)
MY_PUBLIC_KEY = (3361, 20989)
HOST = "127.0.0.1"
MY_PORT = 9100

NTP_SERVER_IP = "in.pool.ntp.org"

CLIENT_PUBLIC_KEY = (3459, 7387)
SERVER_PUBLIC_KEY = (523, 12827)
REGISTRAR_PUBLIC_KEY = (491, 12091)
DIRECTOR_PUBLIC_KEY = (437, 14279)

CLIENT_PUBLIC_KEY_MAP = {
    CLIENT_ID: CLIENT_PUBLIC_KEY,
    SERVER_ID: SERVER_PUBLIC_KEY,
    REGISTRAR_ID: REGISTRAR_PUBLIC_KEY,
    DIRECTOR_ID: DIRECTOR_PUBLIC_KEY
}


def ServeClient(client, addr):
    request = client.recv(2048).decode()
    print("Request received: {}".format(request))
    requestID, requestTargetID, requestTime, requestDuration, requestNonce = request.split("|")[0], request.split("|")[1], request.split("|")[2], request.split("|")[3], request.split("|")[4]

    currentTime = myTime.GetCurrentTime(NTP_SERVER_IP)
    print("Time message was sent: {}".format(requestTime))
    print("Duration of validity: {}".format(requestDuration))
    print("Current Time: {}".format(currentTime))
    if float(requestTime) + float(requestDuration) >= currentTime:
        print("Duration check passed for request from ID: {}, sending public key of ID: {}".format(requestID, requestTargetID))
    else:
        print("Duration check failed for request from ID: {}".format(requestID))
        exit(0)

    requestPublicKey = CLIENT_PUBLIC_KEY_MAP[requestTargetID]

    responsePlaintext = str(requestPublicKey[0]) + "|" + str(requestPublicKey[1]) + "|" + requestID + "|" + requestTargetID + "|" + str(myTime.GetCurrentTime(NTP_SERVER_IP)) + "|" + "900" + "|" + requestNonce
    responseHash = hashlib.sha256(responsePlaintext.encode()).hexdigest()
    responseDigitalSignature = myRSA.Encrypt(responseHash, MY_PRIVATE_KEY)
    response = responsePlaintext + "|" + responseDigitalSignature

    print("Sending response: {}".format(response))
    print("-" * 50)
    client.sendall(response.encode())
    client.close()


def RunPKDA():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, MY_PORT))
    serverSocket.listen(5)
    print("-" * 50)
    print("PKDA listening at {} on port {}".format(serverSocket.getsockname()[0], serverSocket.getsockname()[1]))

    while True:
        client, addr = serverSocket.accept()
        threading.Thread(target=ServeClient, args=(client, addr)).start()


if __name__ == "__main__":
    RunPKDA()
