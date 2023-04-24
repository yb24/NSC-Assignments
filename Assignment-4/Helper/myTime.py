import ntplib


def GetCurrentTime(ntpServerIp):
    c = ntplib.NTPClient()
    response = c.request(ntpServerIp, version=3)
    return response.tx_time
