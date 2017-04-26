import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, ARP
               
def main():
    
    iface = sys.argv[1]
    pkt = Ether() / ARP(op=ARP.who_has, psrc="10.0.0.1", pdst="10.0.1.0")
    pkt.show()    
    sendp(pkt, iface=iface)
    

if __name__ == '__main__':
    main()
