from scapy.all import *

def sniffing(pkt):
	print("source IP: {} <http> Dest IP: %s"%(pkt[IP].src,pkt[IP].dst))

sniff(filter='tcp port 80',prn=sniffing)

