import socket
import time
import os
import random
import requests
from scapy.all import *
from scapy.layers.inet import ICMP, IP


def sendPing():
    ip = 'localhost'
    send(IP(dst = ip, src = 'localhost') / ICMP(type = 8) / (b"put data here") )

sendPing()