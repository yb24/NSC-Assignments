import socket
import struct
import time
from datetime import datetime


def RequestTimeFromNtp(addr='in.pool.ntp.org'):
    REF_TIME_1970 = 2208988800  # Reference time
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = b'\x1b' + 47 * b'\0'
    client.sendto(data, (addr, 123))
    data, address = client.recvfrom(1024)
    if data:
        x = struct.unpack('!12I', data)
        print(x)
        t = x[10]
        t -= REF_TIME_1970
    client.close()
    print(datetime.fromtimestamp(t).strftime("%a %b %d %Y %H:%M:%S.%f"))
    return time.ctime(t), t


if __name__ == "__main__":
    print(RequestTimeFromNtp())
