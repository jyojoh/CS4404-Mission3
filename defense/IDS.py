from scapy.all import *

interface="ens3"
Device_IP = "10.64.13.2"
MAC_Interface = get_if_hwaddr(interface)

def handlePacket(packet):
    print(packet.summary())
    if ICMP in packet:
        if Raw in packet:
            try:
                data = packet[Raw].load.decode()
            except:
                allowPacket(packet)
                return
            if "botreply" in data:
                denyPacket(packet, "Known bot reply")
                return
    allowPacket(packet)

def allowPacket(packet):
    if not IP in packet:
        return
    # Continue to next hop
    packet[Ether].src = MAC_Interface              # MAC of this device
    packet[Ether].dst = getmacbyip(packet[IP].dst) # MAC of destination IP

    del packet.chksum
    packet = packet.__class__(bytes(packet))

    #packet.show2()
    sendp(packet, iface=interface, verbose=False)

def denyPacket(packet, reason):
    print(f"\033[1;31mPacket denied: {reason}")
    print("Details of rejected packet:")
    packet.show()
    print("\033[0;0m")

if __name__ == "__main__":
    print("Running IDS on interface: " + interface + " (" + MAC_Interface + ")")
    sniffFilter = "ether dst " + MAC_Interface + " and not dst " + Device_IP
    print("Analyzing packets with filter: " + sniffFilter)
    sniff(iface=interface, prn=handlePacket, filter=sniffFilter)
