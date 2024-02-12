#!/usr/bin/env python3

from scapy.all import *
import sys
from sys import stdin

conf.checkIPaddr=False
#configuration
localiface = sys.argv[1] 
releaseMAC = sys.argv[2]
releaseIP = sys.argv[3]
serverIP = sys.argv[4]

def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
        NEED TO DO THIS BECAUSE CHADDR EXPECTS A BYTE, IF YOU PUT THE MAC DIRECTLY,
        THEM THIS STRING IS TREATED AS BYTE, WHEN IT IS NOT BYTE, THATS WHY YOU MUST
        SEND A BYTE.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")

#releaseMAC = hex(int(releaseMAC.replace(':',''), 16))
print (releaseMAC)

releaseMACraw = mac_to_bytes(releaseMAC)
print (releaseMACraw)

#craft and send DHCP RELEASE 
dhcp_release = IP(dst=serverIP)/UDP(sport=68,dport=67)/BOOTP(chaddr=releaseMACraw, ciaddr=releaseIP, xid=RandInt())/DHCP(options=[('message-type','release'), 'end'])
print(BOOTP)
send(dhcp_release)