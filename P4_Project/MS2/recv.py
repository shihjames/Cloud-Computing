import sys
import struct
import os
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Packet, IPOption
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Ether, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import BitField, ShortField, IntField, bind_layers

KVSQUERY_PROTOCOL = 200
TCP_PROTOCOL = 6
RESPONSE_PROTOCOL = 0x1234

# Packet used to send request information for the query
class API(Packet):
    name = "API"
    fields_desc= [BitField("protocol", 0, 8),
                IntField("key", 0),
                IntField("key2", 0),
                IntField("value", 0),
                BitField("switchID", 0, 2),                
                BitField("pingPong", 0, 2),
                BitField("queryType", 0, 2),
                BitField("padding", 0, 2)]

# Packet used to return query results as a response header
class Response(Packet):
    name = "Response"
    fields_desc= [IntField("value", 0),
                BitField("isNull", 0, 1),
                BitField("nextType", 0, 1),
                BitField("padding", 0, 6)]

bind_layers(Ether, Response, type=RESPONSE_PROTOCOL)
bind_layers(Response, Response, nextType = 0)
bind_layers(Response, IP, nextType = 1)
bind_layers(IP, API, proto = KVSQUERY_PROTOCOL)
bind_layers(API, TCP, protocol = TCP_PROTOCOL)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

#get packet layers
def pkt_layer(pkt):
    cnt = 0
    while True:
        layer = pkt.getlayer(cnt)
        if layer is None:
            break

        yield layer
        cnt += 1

def handle_pkt(pkt):
    ##TODO: Implement this function
    if API in pkt and pkt[API].padding == 1:
        if pkt[API].pingPong == 2:
            print(f"[Pong]: Received by Switch {pkt[API].switchID}")
            return
        if pkt[API].pingPong == 3:
            print(f"[Ping/Pong] are not in bound, failed in Switch {pkt[API].switchID}")
            return

        if pkt[API].queryType == 0:
            print(f"Switch {pkt[API].switchID}")
            if pkt[Response].isNull == 0:
                print ("NO VALUE") 
            else:
                print (pkt[Response].value)

        elif pkt[API].queryType == 1:
            print(f"Switch {pkt[API].switchID}")
            print ('STORE VALUE SUCCEED')

        elif pkt[API].queryType == 2:
            print ("Switch " + str(pkt[API].switchID))
            for layer in reversed(list(pkt_layer(pkt))):
                if layer.name == "Response" and layer.nextType == 0:
                    if layer.isNull == 0:
                        print ("NO VALUE")
                    else:
                        print (layer.value)
        sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = list(ifaces)[0]
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))



if __name__ == '__main__':
    main()
