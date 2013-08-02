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

conf.verb = 0
loadedModules = []

def analyze(packet):
    try:
        for loadedModule in loadedModules:
            loadedModule.processPacket(packet)
    except:
        pass

def startSniffing(interface):

    print "[*] Start sniffind on %s" % interface
    try:
        sniff(prn=analyze, store=0, iface=interface, filter="tcp")
    except KeyboardInterrupt:
        print "[*] Stop Sniffing"
        sys.exit(0)

def loadModules(path, modulesToLoad):
    print "[*] Loading modules"
    files = glob.glob(path + "*")
    for file in files:
        fileName, fileExtension = os.path.splitext(file)
        if not fileName.endswith("__init__") and fileExtension == ".py" and (modulesToLoad == None or (fileName.replace(path, "").split(".")[-1] in modulesToLoad.replace(" ", "").split(","))):
            moduleName = fileName.replace("/", ".")
            mod = __import__(moduleName)
            modules = moduleName.split(".")
            for module in modules[1:]:
                mod = getattr(mod, module)
            loadedModules.append(mod.module())
            if modulesToLoad != None:
                print "    |-Using %s" % loadedModules[-1].moduleName
    if modulesToLoad == None:
        print "    |-Using all modules"

def listModules():
    print "[*] List of all modules"
    for module in loadedModules:
        print "    |-%s" % module.getDescription()

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Simple live network sniffer')
    parser.add_argument('-i', '--interface', action="store", dest="interface", default=None, help='input interface')
    parser.add_argument('-m', '--modules', action="store", dest="modules", default=None, help='Modules to load (None = all)')
    parser.add_argument('-l', '-list', action="store_true", dest="list", default=False, help='List all modules')
    args = parser.parse_args()

    loadModules('modules/', args.modules)

    if args.list:
        listModules()
        sys.exit(0)

    if os.geteuid() != 0:
        print "[!] You must be root for sniffing network"
        sys.exit(0)

    if args.interface != None:
        startSniffing(args.interface)
    else:
        print "[!] You must enter a valid interface using -i (ex: -i mon0)"
        sys.exit(0)
