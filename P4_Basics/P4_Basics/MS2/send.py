#!/usr/bin/env python3
import random
import socket
import sys
import string
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
from MyHeader import *


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def generateStr(len):
    length = random.randint(len, len*10)
    let = string.ascii_letters
    return ''.join(random.choice(let) for _ in range(length))


def main():
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    for _ in range(100):

        print("sending on interface %s to %s" % (iface, str(addr)))
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        # pkt = pkt / MyHeader() / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / sys.argv[2]
        pkt = pkt / MyHeader() / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152, 65535)) / generateStr(20)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()