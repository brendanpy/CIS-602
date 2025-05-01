from scapy.all import *
import pandas as pd
from scipy.stats import entropy

def parsePacket(packet):
    #clear packet info for each packet
    packet_info = {
        'ttl': 0,
        'len': 0,
        'sport': 0,
        'dport': 0,
        'flags': 0,
        'entropy': 0,
    }
    
    if packet.haslayer("IP"):
        # Get IP layer information
        ip_layer = packet["IP"]
        raw = list(ip_layer.original)

        packet_info['ttl'] = ip_layer.ttl# Time to live
        packet_info['len'] = ip_layer.len # Packet length
        
          # Check if the PACKET is TCP
        if packet.haslayer("TCP"):

            #print(f"Packet Type: TCP")
            tcp_layer = packet["TCP"]
            packet_info['sport'] = tcp_layer.sport #Source port
            packet_info['dport'] = tcp_layer.dport #Destination port
            packet_info['flags'] = tcp_layer.flags.value #TCP flags
            packet_info['entropy'] = entropy(list(tcp_layer.original)) #Shannon entropy of payload

            packetFrame = pd.DataFrame([packet_info])

            packetFrame.to_csv("TCP_Capture.csv", mode='a', header=False, index=False) #append packet info as row to CSV

if not os.path.exists("TCP_Capture.csv"):
    pd.DataFrame(columns=['ttl', 'len', 'sport', 'dport', 'flags', 'entropy']).to_csv("TCP_Capture.csv", index=False)

sniff(iface="en11", prn= parsePacket, store=False) #sniff on en11 interface with calllback to parsePacket