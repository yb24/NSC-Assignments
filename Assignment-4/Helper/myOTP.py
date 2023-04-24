import string
import secrets
import smtplib
import os
from Helper import myTime


def generateAndSendOTP(email, NTP_SERVER_IP):
    digits = string.digits + string.ascii_uppercase
    OTP = ""

    for i in range(8):
        OTP += digits[secrets.randbelow(36)]

    msg = 'Subject: {}\n\n{}'.format("Generated OTP for document download: ", OTP + " is your OTP")

    s = smtplib.SMTP("smtp.gmail.com", 587)
    s.starttls()
    s.login(os.getenv('EMAIL'), os.getenv('EMAIL_PWD'))
    s.sendmail(os.getenv('EMAIL_PWD'), email, msg)
    s.close()

    t = str(myTime.GetCurrentTime(NTP_SERVER_IP))

    return OTP, t
