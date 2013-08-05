Simple And Modular Packet Sniffer
=================================

Python / Scapy

TODO :
-----
 - Fix : Catch Ctrl+c and kill threads
 - Change : move ARP poisoning into external class

Usage :
-------
### list available modules :
./main.py -l

    [*] Loading modules
        |-Using all modules
    [*] List of all modules
        |-popCredentials (Sniff POP credentials)
        |-httpCredentials (Sniff HTTP credentials)
        |-ftpCredentials (Sniff FTP credentials)

### Start sniffing with all modules :
sudo ./main.py -i mon0

    [*] Loading modules
        |-Using all modules
    [*] Start sniffind on mon0

### Start sniffing with selected modules :
sudo ./main.py -i mon0 -m "ftpCredentials, popCredentials"

    [*] Loading modules
        |-Using popCredentials
        |-Using ftpCredentials
    [*] Start sniffind on mon0

### Use ARP poisoning ( -a victimIp-routerIp ) :
sudo ./main.py -i eth0 -a 192.168.0.2-192.168.0.1

    [*] Loading modules
        |-Using all modules
    [*] Start arp poisoning
    [*] Start sniffind on eth0

Extend :
--------

### Create module :
touch ./modules/modulename.py

### Base structure
    #!/usr/bin/python
    # -*- coding: utf-8 -*-

    from scapy.all import *

    class module:
        def processPacket(self, packet):
            # write packet analysis here

        def getDescription(self):
            return "%s (%s)" % (self.moduleName, self.moduleDescription) 

        def __init__(self):
            self.moduleName = "module name"
            self.moduleDescription = "Module description"
