import sys
import struct

from scapy.all import sniff, sendp
from scapy.all import Packet
from scapy.all import Ether, ARP

def handle_pkt(pkt):
    print "got a packet"
    pkt.show()

def main():
    iface = sys.argv[1] # "h2-eth0"
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="arp", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
