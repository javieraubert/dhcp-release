#!/usr/bin/python
import socket
import struct
from uuid import getnode as get_mac
from random import randint
import binascii
import argparse
import sys,os
DHCP_TIMEOUT = 10
class DHCP:
    def __init__(self):
        self.transactionID = b''
	self.DHCPServerIdentifier = ''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def DiscoverPacket(self):
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + b'\x00\x26\x9e\x04\x1e\x9b'
        packet += b'\x37\x01\x36'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

    def address2bin(self, address, sep):
	tok = address.split(sep)
	_address = b''
 	for i in range(len(tok)):
		t = int(tok[i])
		_address += struct.pack('!B', t)
	return _address
    def getMacInBytes(self, _hw_address ):
	# print _hw_address
    	mac = _hw_address
    	macb = b''
    	for i in range(0, 6) :
        	m = int(mac[i], 16)
        	macb += struct.pack('!B', m)
    	return macb

    def ReleasePacket( self, _client_address, hw_address):
	_hw = hw_address.split(':')
	mac = ''.join(_hw) 
	packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'    #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += self.address2bin(_client_address, '.')  #Client Virtual address: xxx.yyy.zzz.aaa
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += self.address2bin(self.DHCPServerIdentifier, '.')   	#server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += self.getMacInBytes(  _hw )   #Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x07'   #Option: (t=53,l=1) DHCP Message Type = DHCP Release
        packet += b'\x36\x04' + self.address2bin(self.DHCPServerIdentifier, '.')
        packet += b'\xff'   #End Option
        return packet

    def check_res(self, data):
 	_id = map(lambda x:x.encode('hex'), data[245:249])
 	self.DHCPServerIdentifier = '.'.join(map(lambda x:str(int(x,16)), _id[0:4]))
	if self.DHCPServerIdentifier: 
		return True 
	return False

    def getServerIdentifier(self):
	_sid = self.DHCPServerIdentifier
	return _sid

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--client-ip', help='must be in the format xxx.yyy.zzz.aaa', required=True,action="store", dest="client_ip",type=str)
    parser.add_argument('--mac', help = 'must be in the format 00:26:9e:04:1e:9b', required=True, action="store", type=str)
    parser.add_argument('--dhcp-broadcast-ip', help = 'must be in the dhcp broadcast', required=True, action="store", type=str)
    args = parser.parse_args()
    # Initializing Socket
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #Broadcast
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #Reuse Addr

    try:
        dhcps.bind(('', 68))
    except Exception as e:
        print('Port 68 in use...')
        dhcps.close()
	sys.exit(os.EX_SOFTWARE)    
 
    dhcp = DHCP()	
    dhcps.sendto(dhcp.DiscoverPacket(), (args.dhcp_broadcast_ip, 67))
    dhcps.settimeout(DHCP_TIMEOUT)
    print('DHCP Discover......................, Waiting for 10sec')
    try:
        while True:
            data = dhcps.recv(1024)
	    dhcp.check_res(data)
	    DHCPServerID = dhcp.getServerIdentifier()
	    print "--------Got DHCP - Server ID-------- =>" , DHCPServerID
    	    dhcps.sendto(dhcp.ReleasePacket(args.client_ip, args.mac),(DHCPServerID, 67) ) 
            print('DHCP Release.......................')
            print('Exiting!!!!')
	    break
    except socket.timeout as e:
        print(e)
    
    dhcps.close()
    sys.exit(os.EX_OK)   
