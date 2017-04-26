import sys
import struct

from scapy.all import sniff
from scapy.all import Packet
from scapy.all import IP, UDP, Raw

    
def main():
    print "sniffing..." 
    sys.stdout.flush()
    sniff(iface = 'h2-eth0', prn = lambda pkt: pkt.show())

if __name__ == '__main__':
    main()
