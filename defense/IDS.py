from scapy.all import *
from scapy.layers.inet import ICMP, IP
import time
from multiprocessing import Process

destIP = 'localhost'
srcIP = 'localhost'
interface = '\\Device\\NPF_Loopback'

def processPacket(packet):
    if ICMP in packet:
        if Raw in packet:
            data = packet[Raw].load.decode()
            if "botreply" in data:
                return
            else:
                send(packet)

def sniffForPacket():
    sniff(iface=interface, prn=processPacket, filter='icmp')

if __name__ == '__main__':
    p = Process(target=sniffForPacket)
    p.start()


