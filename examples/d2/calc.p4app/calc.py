#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send
from scapy.all import Packet
from scapy.all import Ether, StrFixedLenField, XByteField, IntField
from scapy.all import bind_layers

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

class NumParseError(Exception):
    pass

class OpParseError(Exception):
    pass

class Token:
    def __init__(self,type,value = None):
        self.type = type
        self.value = value

def make_num_parser():
    def parse(s, i, ts):
        pattern = "^\s*([0-9]+)\s*"
        match = re.match(pattern,s[i:])
        if match:
            ts.append(Token('num', match.group(1)))
            return i + match.end(), ts
        raise NumParseError('Expected number literal.')
    return parse


def make_op_parser():
    def parse(s, i, ts):
        pattern = "^\s*([-+&|^])\s*"
        match = re.match(pattern,s[i:])
        if match:
            ts.append(Token('num', match.group(1)))
            return i + match.end(), ts
        raise NumParseError("Expected binary operator '-', '+', '&', '|', or '^'.")
    return parse

def make_seq(p1, p2):    
    def parse(s, i, ts):
        i,ts2 = p1(s,i,ts)
        return p2(s,i,ts2)
    return parse


def main():

    pn = make_num_parser()
    po = make_op_parser()
    p = make_seq(pn, make_seq(po,pn))    
    s = ''
    iface = 'en0'
    
    while True:
        s = str(raw_input('> '))
        if s == "quit":
            break
        print s
        try:
            i,ts = p(s,0,[])
            print i
            print len(ts)
            print ts[0].value
            print ts[1].value
            print ts[2].value
            pkt = Ether(type=0x1234) / P4calc(op=ts[1].value, operand_a=ts[0].value, operand_b=ts[2].value)                
            pkt.show()
            #sendp(pkt, iface=iface)
        except Exception as error:
            print error 

    
if __name__ == '__main__':
    main()
