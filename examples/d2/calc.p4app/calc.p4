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

