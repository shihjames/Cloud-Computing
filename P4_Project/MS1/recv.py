import sys
import os
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Packet, IPOption
from scapy.all import sniff, get_if_list
from scapy.all import ShortField, IntField, BitField, FieldListField, FieldLenField
from scapy.layers.inet import _IPOption_HDR, IP, TCP, Ether
from scapy.all import BitField, ShortField, IntField, bind_layers

KVSQUERY_PROTOCOL = 200
TCP_PROTOCOL = 6
RESPONSE_PROTOCOL = 0x1234

class Response(Packet):
    name = "Response"
    fields_desc= [IntField("value", 0),
                  BitField("isNull", 0, 1),
                  BitField("nextType", 0, 1),
                  BitField("padding", 0, 6)]

class API(Packet):
    name = "API"
    fields_desc= [BitField("protocol", 0, 8),
                  IntField("key", 0),
                  IntField("key2", 0),
                  IntField("value", 0),
                  IntField("versionNum", 0),
                  BitField("switchID", 0, 2),
                  BitField("pingPong", 0, 2),
                  BitField("queryType", 0, 2),
                  BitField("padding", 0, 2)]

bind_layers(Ether, Response, type=RESPONSE_PROTOCOL)
bind_layers(Response, Response, nextType = 0)
bind_layers(Response, IP, nextType = 1)
bind_layers(IP, API, proto = KVSQUERY_PROTOCOL)
bind_layers(API, TCP, protocol = TCP_PROTOCOL)

def get_if():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_packet_layers(packet):
    counter = 0
    while 1:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1

def handle_pkt(pkt):
    if API in pkt and pkt[API].padding == 1:
        if pkt[API].queryType == 0:
            if pkt[Response].isNull == 0:
                print("NO VALUE")
            else:
                print(pkt[Response].value)
        elif pkt[API].queryType == 1:
            if pkt[Response].isNull == 1:
                print("STORE VALUE FAILED, VERSION SHOULD ONLY BE [0-5]")
            else:
                print('STORE VALUE SUCCEED.')
        
        elif pkt[API].queryType == 2:
            for layer in reversed(list(get_packet_layers(pkt))):
                if layer.name == "Response" and layer.nextType == 0:
                    if layer.isNull == 0:
                        print("NO VALUE")
                    else:
                        print(layer.value)
        sys.stdout.flush()

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface,
          prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()