# https://stackoverflow.com/questions/18743962/python-send-udp-packet

import socket
import time
import itertools

UDP_IP = "128.105.144.254"
UDP_PORT = 81

MESSAGE = bytes(list(map(ord, "HI MASOT")))

def to_bytes_(integer):
    if integer == 0:
        return []
    return to_bytes_(integer // 256) + [integer % 256]

def to_bytes(integer):
    b = to_bytes_(integer)
    return bytes([0 for i in range(8 - len(b))] + b)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
for i in itertools.count():
    print(i)
    sock.sendto(MESSAGE + to_bytes(i), (UDP_IP, UDP_PORT))
    time.sleep(0.1)
