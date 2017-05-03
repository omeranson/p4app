import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
    
def main():
    
    addr = socket.gethostbyname(sys.argv[1])
    iface = sys.argv[2]
    pkt =  Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst=addr) / UDP(dport=8000) / "hello"
    pkt.show2()
    sendp(pkt, iface=iface)
    

if __name__ == '__main__':
    main()
