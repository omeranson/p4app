import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, ARP

class P4calc(Packet):
    name = "P4calc"
    fields_desc = [ StrFixedLenField("H", "H", length=1),
                    StrFixedLenField("P", "P", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("op", "+", length=1),
                    IntField("operand_a", 0),
                    IntField("operand_b", 0),
                    IntField("result", 0xDEADBABE)]

bind_layers(Ether, P4calc, type=0x1234)
               
def main():
    
    iface = sys.argv[1]
    pkt = Ether() / ARP(op=ARP.who_has, psrc="10.0.0.1", pdst="10.0.1.0")
    pkt.show()    
    sendp(pkt, iface=iface)
    

if __name__ == '__main__':
    main()
