import pandas as pd
from scapy.all import *
from scipy.stats import entropy
from sklearn.ensemble import IsolationForest
from rich import print
from sklearn.preprocessing import StandardScaler

def realtimePredict(packet):
 
    packet_info = {
        'ttl': 0,
        'len': 0,
        'sport': 0,
        'dport': 0,
        'flags': 0,
        'entropy': 0
    }
    
    if packet.haslayer("IP"):
        
        ip_layer = packet["IP"]
        raw = list(ip_layer.original)

        packet_info['ttl'] = ip_layer.ttl
        packet_info['len'] = ip_layer.len

        
        # Check if the PACKET is TCP
        if packet.haslayer("TCP"):

            #print(f"Packet Type: TCP")
            tcp_layer = packet["TCP"]
            packet_info['sport'] = tcp_layer.sport #Source port
            packet_info['dport'] = tcp_layer.dport #Destination port
            packet_info['flags'] = tcp_layer.flags.value #TCP flags
            packet_info['entropy'] = entropy(list(tcp_layer.original)) #Shannon entropy of payload


            if(packet_info['dport'] == 9999 or packet_info['sport'] == 9999): #Python server port
                print(f"Debug Break")

        
            packetFrame = pd.DataFrame([packet_info])

            scaled_packet = scaler.transform(packetFrame)

            result = forest.predict(scaled_packet)
            if result[0] == -1:
                print(f"[red]Anomaly detected[/]\n{packet.summary()}")
            else:
                print("[green]Normal packet[/]")


trainingData = pd.read_csv("TCP_Capture.csv")
 
scaler = StandardScaler()
scaled_data = scaler.fit_transform(trainingData[['ttl', 'len', 
                         'sport', 'dport', 'flags', 
                          'entropy']])

forest = IsolationForest(contamination=0.1)
forest.fit(scaled_data)

sniff(iface="en11", prn=realtimePredict, store=False)