import socket
import time
import os
import random
import requests
from scapy.all import *
from scapy.layers.inet import ICMP, IP


def sendPing():
    ip = 'localhost'
    packet = IP(dst = ip, src = 'localhost') / ICMP(type = 8) / (b"comm")
    packet.show2()
    send(packet)

def processPacket(packet):
    if packet[ICMP].type == 0:
        if Raw in packet:
            packet.show()
            data = packet[Raw].load().decode()
            print(data)

while True:
    sendPing()
    sniff(iface='\\Device\\NPF_Loopback', prn=processPacket, filter="icmp")

    waitTime = 5
    time.sleep(waitTime)