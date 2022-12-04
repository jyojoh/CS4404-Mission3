import socket
import time
import os
import random
import requests
from scapy.all import *
from scapy.layers.inet import ICMP


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
    r = requests.get(url = address)

def sendPostRequest():
    address = 'localhost'
    data = ''
    r = requests.post(url = address, data = data)

def sendICMPPing():
    address = 'localhost'
    response = os.system("ping -c 1 " + address)

def dnsARecord():
    address = 'localhost'
    site = 'example.com'
    os.system('dig @' + address + ' ' + site)

def processPacket(packet):
    if ICMP in packet:
        if Raw in packet:
            data = packet[Raw].load.decode()
            if 'put data here' in data:
                #send a file
                return

def sniffForPacket():
    interface = ''
    sniff(iface= interface, prn= processPacket(), filter='icmp')

functionList = [connectToAdversary(), sendGetRequest(), sendPostRequest(), sendICMPPing(), dnsARecord()]

while True:
    sniffForPacket()

    waitTime = random.randint(1, 10)
    time.sleep(waitTime)

    random.choice(functionList)


