#!/usr/bin/env python
from scapy.all import BitField, ShortField, IntField, bind_layers
from scapy.layers.inet import _IPOption_HDR
from scapy.all import IP, TCP, UDP, Ether, Raw
from scapy.all import (
    ShortField,
    IntField,
    LongField,
    BitField,
    FieldListField,
    FieldLenField,
)
from scapy.all import Packet, IPOption
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
import sys
import struct
import os
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


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


def helper(packet):
    layers = []
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        layers.append(layer)
        counter += 1

    return layers


def handle_pkt(pkt):
    if API in pkt and pkt[API].headerPad == 1:
        if pkt[API].accessType == 1:
            if pkt[API].queryType == 2 and pkt[API].rangeKey == pkt[API].uBound:
                print("No Access: Host " +
                      str(pkt[API].hostID) + " has no read access at in this range")
            elif pkt[API].queryType != 2:
                print(
                    "No Access: Host "
                    + str(pkt[API].hostID)
                    + " has no read access at key "
                    + str(pkt[API].key)
                )
            sys.stdout.flush()
            return

        if pkt[API].accessType == 2:
            print("No Access: Host " + str(pkt[API].hostID) +
                  " has no write access at key " + str(pkt[API].key))
            sys.stdout.flush()
            return

        if pkt[API].packetType == 2:
            sys.stdout.flush()
            return

        if pkt[API].packetType == 3:
            sys.stdout.flush()
            return

        if pkt[API].queryType == 0:
            if pkt[Response].keyExists == 0:
                print("Get: " + str(pkt[API].key) + " not exists")
            else:
                print("Get: [" + str(pkt[API].key) +
                      ", " + str(pkt[Response].value) + "]")

        elif pkt[API].queryType == 1:
            print("Put: [" + str(pkt[API].key) +
                  ", " + str(pkt[API].value) + "]")

        elif pkt[API].queryType == 2:
            for layer in reversed(helper(pkt)):
                if layer.name == "Response":
                    if layer.keyExists == 0:
                        print("Range: " + str(pkt[API].key) + " not exists")
                    else:
                        print("Range: " + str(layer.value))
        print("=====================")
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir("/sys/class/net/") if "eth" in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == "__main__":
    main()
