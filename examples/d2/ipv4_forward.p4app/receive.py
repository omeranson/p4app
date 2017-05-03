import sys
import struct

from scapy.all import sniff, sendp, hexdump
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def handle_pkt(pkt):
    print "got a packet"

    pkt.show2()
#    hexdump(pkt)
    sys.stdout.flush()


def main():
    iface = sys.argv[1] # "h2-eth0"
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 8000", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
