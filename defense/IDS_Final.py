from scapy.all import *
import socket, struct

interface="ens3"
Device_IP = "10.64.13.2"
MAC_Interface = get_if_hwaddr(interface)

IP_Dict = {}

def handlePacket(packet):
    if IP not in packet:
        return

    print(packet.summary())

    # Check for invalid protocol field
    if packet[IP].proto > 144 and packet[IP].proto < 253:
        return denyPacket(packet, "Invalid protocol field: IP.proto=" + str(packet[IP].proto))

    #Check for invalid packet length
    if len(packet) != packet[IP].len+14:
        return denyPacket(packet, "Invalid packet length field in IP header. Expected IP.len= "+str(len(packet)-14)+", got IP.len="+str(packet[IP].len))

    #Check for invalid IPv4 packet header length
    if packet[IP].ihl < 5:
        return denyPacket(packet, "Invalid IPv4 packet header length. Expected IP.ihl >= 5, got IP.ihl = "+str(packet[IP].ihl))

    #Check for reserved IP address
    # 224.0.0.0 - 239.255.255.255
    # 240.0.0.0 - 255.255.255.255
    # 0.0.0.0   - 0  .255.255.255
    # 127.0.0.0 - 127.255.255.255
    packedIP = socket.inet_aton(packet[IP].src)
    longIP = struct.unpack("!L", packedIP)[0]
    sigIP = (longIP & 0xFF000000) >> 24
    if (224 <= sigIP and sigIP <= 255) or sigIP == 0 or sigIP == 127:
        return denyPacket(packet, "Source IP ("+packet[IP].src+") came from reserved IP")

    if ICMP in packet:
        if Raw in packet:
            try:
                data = packet[Raw].load.decode()
            except:
                return allowPacket(packet)
            if "botreply" in data:
                return denyPacket(packet, "Known bot reply")
            elif "command" in data:
                return denyPacket(packet, "Known C2 communication")
        if packet[IP].src in IP_Dict:
            prevID = IP_Dict[packet[IP].src]
            curID = packet[IP].id
            if (not (0xFFFF - prevID < 1000)) and curID < prevID: # Check for covert channel
                return denyPacket(packet, "ID not increasing, potential C2 message.\nPrevious ID: " + str(prevID) + ", Current ID: " + str(curID))
            IP_Dict[packet[IP].src] = curID # Update ID
        else:
            IP_Dict[packet[IP].src] = packet[IP].id # Set ID
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
