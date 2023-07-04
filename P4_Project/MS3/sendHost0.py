#!/usr/bin/env python
from scapy.all import BitField, ShortField, IntField, bind_layers
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.all import Packet
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
import argparse
import sys
import socket
import random
import struct
import string
import time
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


ADDR = "10.0.1.1"
QUERY_PROTOCOL = 250
API_PROTOCOL = 200
TCP_PROTOCOL = 6
RESPONSE_PROTOCOL = 0x1234


class API(Packet):
    name = "API"
    fields_desc = [
        BitField("protocol", 0, 8),
        IntField("key", 0),
        IntField("rangeKey", 0),
        IntField("value", 0),
        IntField("uBound", 0),
        IntField("hostID", 0),
        BitField("SID", 0, 2),
        BitField("packetType", 0, 2),
        BitField("queryType", 0, 2),
        BitField("accessType", 0, 7),
        BitField("headerPad", 0, 3)
    ]


class Response(Packet):
    name = "Response"
    fields_desc = [
        IntField("key", 0),
        IntField("value", 0),
        BitField("keyExists", 0, 1),
        BitField("isLast", 0, 1),
        BitField("headerPad", 0, 6),
    ]


bind_layers(Ether, Response, type=RESPONSE_PROTOCOL)
bind_layers(Response, Response, isLast=0)
bind_layers(Response, IP, isLast=1)
bind_layers(IP, API, proto=API_PROTOCOL)
bind_layers(API, TCP, protocol=TCP_PROTOCOL)


def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def handleQuery(addr, iface, lower, upper, size):
    if upper > 1025 or lower > 1025 or upper < 0 or lower < 0 or lower > upper:
        print("Invalid range")
        exit(1)

    i = lower
    while i < upper - size:
        pkt = Ether(src=get_if_hwaddr(iface),
                    dst='ff:ff:ff:ff:ff:ff', type=RESPONSE_PROTOCOL)
        pkt = pkt / Response(isLast=1)
        pkt = pkt / IP(dst=addr, proto=API_PROTOCOL) / API(protocol=TCP_PROTOCOL,
                                                           queryType=2, key=i, rangeKey=i+size, uBound=upper, hostID=0)
        pkt = pkt / \
            TCP(dport=1234, sport=random.randint(49152, 65535)) / "range"
        sendp(pkt, iface=iface, verbose=False)
        i += size

    pkt = Ether(src=get_if_hwaddr(iface),
                dst='ff:ff:ff:ff:ff:ff', type=RESPONSE_PROTOCOL)
    pkt = pkt / Response(isLast=1)
    pkt = pkt / IP(dst=addr, proto=API_PROTOCOL) / API(protocol=TCP_PROTOCOL,
                                                       key=i, rangeKey=upper, uBound=upper, queryType=2, hostID=0)
    pkt = pkt / TCP(dport=1234, sport=random.randint(49152, 65535)) / "range"
    sendp(pkt, iface=iface, verbose=False)


def main():
    if len(sys.argv) < 2:
        print("Invalid request format")
        exit(1)

    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(ADDR)))

    if sys.argv[1] == "get":
        if len(sys.argv) < 3:
            print("Missing argument [key]")
            exit(1)

        if int(sys.argv[2]) > 1024 or int(sys.argv[2]) < 0:
            print("Invalid argument")
            exit(1)

        pkt = Ether(src=get_if_hwaddr(iface),
                    dst="ff:ff:ff:ff:ff:ff", type=RESPONSE_PROTOCOL)
        pkt = pkt / Response(isLast=1)
        pkt = (pkt / IP(dst=ADDR, proto=API_PROTOCOL) / API(protocol=TCP_PROTOCOL, queryType=0,
               key=int(sys.argv[2]), hostID=0) / TCP(dport=1234, sport=random.randint(49152, 65535)) / "get")
        sendp(pkt, iface=iface, verbose=False)

    elif sys.argv[1] == "put":
        if len(sys.argv) < 4:
            print("Missing arguments, [key] and [value]")
            exit(1)
        if int(sys.argv[2]) > 1024 or int(sys.argv[2]) < 0:
            print("Invalid argument")
            exit(1)
        pkt = Ether(
            src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=RESPONSE_PROTOCOL
        )
        pkt = pkt / Response(isLast=1)
        pkt = (pkt / IP(dst=ADDR, proto=API_PROTOCOL) / API(protocol=TCP_PROTOCOL, queryType=1, key=int(
            sys.argv[2]), value=int(sys.argv[3]), hostID=0) / TCP(dport=1234, sport=random.randint(49152, 65535)) / "put")
        sendp(pkt, iface=iface, verbose=False)

    elif sys.argv[1] == "range":
        if len(sys.argv) < 4:
            print("Missing arguments, [key] and [rangeKey]")
            exit(1)
        handleQuery(ADDR, iface, int(sys.argv[2]), int(sys.argv[3]), 10)

    elif sys.argv[1] == "select":
        upper = 0
        lower = 0
        if len(sys.argv) < 4:
            print("Missing arguments, [operator] and [key]")
            exit(1)

        if sys.argv[2] == ">":
            if int(sys.argv[3]) >= 1024:
                print('invalid value')
                exit(1)
            upper = 1025
            lower = int(sys.argv[3]) + 1
        elif sys.argv[2] == ">=":
            upper = 1025
            lower = int(sys.argv[3])
        elif sys.argv[2] == "<":
            if int(sys.argv[3]) <= 0:
                print('invalid value')
                exit(1)
            upper = int(sys.argv[3])
            lower = 0
        elif sys.argv[2] == "<=":
            upper = int(sys.argv[3]) + 1
            lower = 0
        elif sys.argv[2] == "==":
            upper = int(sys.argv[3]) + 1
            lower = int(sys.argv[3])
        handleQuery(ADDR, iface, lower, upper, 10)


if __name__ == "__main__":
    main()
