import sys
import struct

from scapy.all import sniff, sendp, hexdump
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

# import socket, sys
# import struct

# sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# sock.bind(('', int(sys.argv[1])))

# while True:
#     try:
#         data, addr = sock.recvfrom(1024)
#     except KeyboardInterrupt:
#         sock.close()
#         break
#     count = struct.unpack(">I", data[0:4])[0]
#     print "count = %d" % count
#     for i in range(1,count+1):
#         lhs = 4 * i
#         rhs = lhs+4
#         swid = struct.unpack(">I", data[lhs:rhs])[0]
#         print "    swid = %d" % swid
#     lhs = 4 * count + 4
#     load = data[lhs:]
#     print "msg = %s" % load
#     sys.stdout.flush()

def handle_pkt(pkt):
    print "got a packet"
    #pkt = str(pkt)
    #print pkt

    pkt.show2()
    hexdump(pkt)
    sys.stdout.flush()
    data = pkt[Raw].load
    print "------------"
    print str(data)
    # count = struct.unpack(">I", data[0:4])[0]
    count = struct.unpack(">I", data[0:4])[0]
    print "count = %d" % count
    for i in range(1,count+1):
        lhs = 4 * i
        rhs = lhs+4
        # swid = struct.unpack(">I", data[lhs:rhs])[0]
        swid = struct.unpack(">I", data[lhs:rhs])[0]
        print "    swid = %d" % swid
    lhs = 4 * count + 4
    load = data[lhs:]
    print "msg = %s" % load
    sys.stdout.flush()


def main():
    iface = sys.argv[1] # "h2-eth0"
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 8000", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
