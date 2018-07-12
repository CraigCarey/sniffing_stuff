#!/usr/bin/env python

from scapy.all import *

def PacketHandler(pkt):
	
	if pkt.type == 0 and pkt.subtype == 4:
		print "Client with MAC: %s probing for SSID: %s" % (pkt.addr2, pkt.info)

sniff(iface='wlx00c0ca526067', prn = PacketHandler)
