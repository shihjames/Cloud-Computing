import sys
import random
import logging
from scapy.all import sendp, get_if_list, get_if_hwaddr, Packet, Ether, IP, TCP, BitField, IntField, bind_layers

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

KVSQUERY_PROTOCOL = 200
TCP_PROTOCOL = 6
RESPONSE_PROTOCOL = 0x1234

# Packet used to send request information for the query
class API(Packet):
    name = "API"
    fields_desc= [BitField("protocol", 0, 8),
                  IntField("key1", 0),
                  IntField("key2", 0), 
                  IntField("value", 0),
                  IntField("versionNum", 0),
                  BitField("switchID", 0, 2),
                  BitField("pingPong", 0, 2),
                  BitField("queryType", 0, 2),
                  BitField("padding", 0, 2)]

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
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def splitRange(addr, iface, lower, upper, versionNum, size = 10):
    if upper > 1025 or lower > 1025 or upper < 0 or lower < 0 or lower > upper:
        print("invalid value")
        exit(1)

    i = lower
    while i < upper - size:
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=RESPONSE_PROTOCOL)
        pkt = pkt / Response(nextType = 1)
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / API(protocol=TCP_PROTOCOL, queryType=2, key1=i, key2=i+size, versionNum=versionNum)
        pkt = pkt / TCP(dport=1234, sport=random.randint(49152,65535)) / "range"
        sendp(pkt, iface=iface, verbose=False)
        i += size

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=RESPONSE_PROTOCOL)
    pkt = pkt / Response(nextType = 1)
    pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / API(protocol=TCP_PROTOCOL, key1=i, key2=upper, queryType=2, versionNum=versionNum)
    pkt = pkt / TCP(dport=1234, sport=random.randint(49152,65535)) / "range"
    sendp(pkt, iface=iface, verbose=False)

def main():

    addr = "10.0.1.1"
    iface = get_if()

    print("sending on interface {0} to address  {1}".format(iface, addr))

    # get request
    if sys.argv[1] == "get":
        if len(sys.argv) < 4:
            print("error: input should be \"get <key> <version number>\"")
            exit(1)
        if int(sys.argv[2]) > 1024 or int(sys.argv[2]) < 0:
            print("error: value should be 0~1024")
            exit(1)
        if int(sys.argv[3]) > 5 or int(sys.argv[3]) < 0:
            print("error: version number should be 0~5")
            exit(1)
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=RESPONSE_PROTOCOL)
        pkt = pkt / Response(nextType = 1)
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / API(protocol=TCP_PROTOCOL, queryType=0, key1=int(sys.argv[2]), versionNum=int(sys.argv[3])) / TCP(dport=1234, sport=random.randint(49152,65535)) / "get"
        sendp(pkt, iface=iface, verbose=False)  
    
    # put request
    elif sys.argv[1] == "put":
        if len(sys.argv) < 4:
            print("error: input should be \"put <key> <value>\"")
            exit(1)
        if int(sys.argv[2]) < 0 or int(sys.argv[2]) > 1024:
            print("error: value should be 0~1024")
            exit(1)
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=RESPONSE_PROTOCOL)
        pkt = pkt / Response(nextType = 1)
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / API(protocol=TCP_PROTOCOL, queryType=1, key1=int(sys.argv[2]), value=int(sys.argv[3])) / TCP(dport=1234, sport=random.randint(49152,65535)) / "put"
        sendp(pkt, iface=iface, verbose=False)
    
    # range request 
    elif sys.argv[1] == "range":
        if len(sys.argv) < 5:
            print("error: input should be \"range <key1> <key2> <version number>\"")
            exit(1)
        if int(sys.argv[4]) > 5 or int(sys.argv[4]) < 0:
            print("error: version number should be 0~5")
            exit(1)
        splitRange(addr, iface, int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    
    # select request 
    elif sys.argv[1] == "select":
        if len(sys.argv) < 5:
            print("error: input should be \"select <operand> <key value> <version number>\"")
            exit(1)
        if int(sys.argv[4]) > 5 or int(sys.argv[4]) < 0:
            print("error: version number should be 0~5")
            exit(1)
        upper = 0
        lower = 0
        if sys.argv[2] == ">":
            upper = 1025
            lower = int(sys.argv[3]) + 1
        elif sys.argv[2] == ">=":
            upper = 1025
            lower = int(sys.argv[3])
        elif sys.argv[2] == "<":
            upper = int(sys.argv[3])
            lower = 0
        elif sys.argv[2] == "<=":
            upper = int(sys.argv[3]) + 1
            lower = 0
        elif sys.argv[2] == "==":
            upper = int(sys.argv[3]) + 1
            lower = int(sys.argv[3])
        else:
            print("error: operand  should be > >= == <= <")
            exit(1)
        splitRange(addr, iface, lower, upper, int(sys.argv[4]))

if __name__ == '__main__':
    main()