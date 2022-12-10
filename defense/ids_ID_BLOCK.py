from scapy.all import *

interface="ens3"
Device_IP = "10.64.13.2"
MAC_Interface = get_if_hwaddr(interface)

IP_Dict = {}

def handlePacket(packet):
    print(packet.summary())
    if ICMP in packet:
        if packet[IP].proto != 1:
            denyPacket(packet, "Incorrect protocol field.")
        if Raw in packet:
            try:
                data = packet[Raw].load.decode()
            except:
                allowPacket(packet)
                return
            if "botreply" in data:
                denyPacket(packet, "Known bot reply")
                return
        if packet[IP].src in IP_Dict:
            prevID = IP_Dict[packet[IP].src]
            curID = packet[IP].id
            if (not (0xFFFF - prevID < 1000)) and curID < prevID: # Check for covert channel
                denyPacket(packet, "ID not increasing, potential C2 message.\nPrevious ID: " + str(prevID) + ", Current ID: " + str(curID))
                return
            IP_Dict[packet[IP].src] = curID # Update ID
        else:
            IP_Dict[packet[IP].src] = packet[IP].id # Set ID
    allowPacket(packet)

def allowPacket(packet):
    if not IP in packet:
        return

    # normalize ttl field in IP header
    if not packet[IP].ttl == 0:
        if packet[IP].ttl < 3:
            packet[IP].ttl = packet[IP].ttl - 1
        else:
            packet[IP].ttl = 3

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
