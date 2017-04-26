import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
    
def main():
    
    pkt =  Ether(dst='ff:ff:ff:ff:ff:ff') / IP(dst='10.0.1.10') / UDP(dport=8000) / "hello"
    pkt.show()
    sendp(pkt, iface='h1-eth0')
    

if __name__ == '__main__':
    main()
