import socket
import myRSA
import threading

SERVER_ID = "6c01891b-02cd-427b-af45-0f144a299780"
CLIENT_A_ID = "971b7595-c9c8-42f4-bf22-1c9c4600f805"
CLIENT_B_ID = "66f06d5e-7e01-4af9-b0fb-e57f79327eda"

SERVER_PRIVATE_KEY = (20041, 20989)
SERVER_PUBLIC_KEY = (3361, 20989)

CLIENT_A_PUBLIC_KEY = (3459, 7387)
CLIENT_B_PUBLIC_KEY = (523, 12827)

CLIENT_PUBLIC_KEY_MAP = {
    CLIENT_A_ID: CLIENT_A_PUBLIC_KEY,
    CLIENT_B_ID: CLIENT_B_PUBLIC_KEY
}

HOST = "127.0.0.1"
SERVER_PORT = 8000


def ServeClient(client, addr):
    request = client.recv(2048).decode()
    requestID = request.split("|")[0]
    requestPublicKey = CLIENT_PUBLIC_KEY_MAP[requestID]
    response = myRSA.Encrypt(str(requestPublicKey[0]) + "|" + str(requestPublicKey[1]) + "|" + request, SERVER_PRIVATE_KEY)
    client.sendall(response.encode())
    client.close()


def RunServer():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((HOST, SERVER_PORT))
    serverSocket.listen(5)
    print("Server listening at {} on port {}".format(serverSocket.getsockname()[0], serverSocket.getsockname()[1]))

    while True:
        client, addr = serverSocket.accept()
        threading.Thread(target=ServeClient, args=(client, addr)).start()

    serverSocket.close()


if __name__ == "__main__":
    RunServer()
