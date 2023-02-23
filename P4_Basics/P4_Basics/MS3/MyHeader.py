from scapy.all import (
    Ether,
    IP,
    Packet,
    BitField,
    bind_layers,
)
import sys
import os

TYPE_MYHEADER = 0x1234
TYPE_IPV4 = 0x0800


class MyHeader(Packet):
    name = "MyHeader"
    fields_desc = [
        BitField("id", 0, 32),
        BitField("protocol", 0, 16),
        BitField("nhop", 0, 32),
        BitField("S1P2", 0, 32),
        BitField("S1P3", 0, 32),
        BitField("S2P1", 0, 32),
        BitField("S3P1", 0, 32),
        BitField("S4P1", 0, 32)
    ]

bind_layers(Ether, MyHeader, type=TYPE_MYHEADER)
bind_layers(MyHeader, IP, protocol=TYPE_IPV4)
