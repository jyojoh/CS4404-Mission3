import socket
import time
import os
import random
import requests
from scapy.all import *


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

functionList = [connectToAdversary(), sendGetRequest(), sendPostRequest(), sendICMPPing(), dnsARecord(), ]

while True:
    waitTime = random.randint(1, 10)
    time.sleep(waitTime)

    random.choice(functionList)


