#!/usr/bin/python
import socket
import struct
from uuid import getnode as get_mac
from random import randint
import sys,os

DHCP_TIMEOUT = 10
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
 
class DHClient(object):
    def __init__(self, _dhcp_broadcast_ip):
        self.BroadCast_IP = _dhcp_broadcast_ip
        self.transactionID = b''
	self.DHCPServerIdentifier = ''
    	self.dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Initializing Socket 
    	self.dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Broadcast
    	self.dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Reuse Addr        
    	try:
        	self.dhcps.bind(('', DHCP_CLIENT_PORT))
    	except Exception as e:
        	print 'Port ' + DHCP_CLIENT_PORT + ' is in use...'
        	self.dhcps.close()
		sys.exit(os.EX_SOFTWARE)    	
	for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def DiscoverPacket(self, _client_address, hw_address):
	_hw = hw_address.split(':')
	mac = ''.join(_hw)        
	packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += self.Address2Bin(_client_address, '.')   #Client IP address: 0.0.0.0
        packet += self.Address2Bin(_client_address, '.')   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        packet += self.GetMacInBytes(_hw)   #Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x37\x01\x36'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

    def Address2Bin(self, address, sep):
	tok = address.split(sep)
	_address = b''
 	for i in range(len(tok)):
		t = int(tok[i])
		_address += struct.pack('!B', t)
	return _address
    def GetMacInBytes(self, _hw_address ):
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
        packet += self.Address2Bin(_client_address, '.')  #Client Virtual address: xxx.yyy.zzz.aaa
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += self.Address2Bin(self.DHCPServerIdentifier, '.')   	#server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += self.GetMacInBytes(_hw)   #Client MAC address: 00:26:9e:04:1e:9b
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x07'   #Option: (t=53,l=1) DHCP Message Type = DHCP Release
        packet += b'\x36\x04' + self.Address2Bin(self.DHCPServerIdentifier, '.')
        packet += b'\xff'   #End Option
        return packet

    def CheckResponse(self, data):
 	_id = map(lambda x:x.encode('hex'), data[245:249])
 	self.DHCPServerIdentifier = '.'.join(map(lambda x:str(int(x,16)), _id[0:4]))
	if self.DHCPServerIdentifier: 
		return True 
	return False

    def SendPacket(self, _virtual_address, _physical_address):
    	self.dhcps.sendto(self.DiscoverPacket(_virtual_address, _physical_address), (self.BroadCast_IP, DHCP_SERVER_PORT))
    	self.dhcps.settimeout(DHCP_TIMEOUT)	
    	print('DHCP Discover......................, Waiting For 10sec')
    	try:
            while True:
            	data = self.dhcps.recv(1024)
	    	self.CheckResponse(data)
	    	DHCPServerID = self.getServerIdentifier()
	        print "--------Got DHCP - Server ID-------- =>" , DHCPServerID
    	    	self.dhcps.sendto(self.ReleasePacket(_virtual_address, _physical_address),(DHCPServerID, DHCP_SERVER_PORT) ) 
            	print('DHCP Release.......................')
            	print('Exiting!!!!')
	    	break
    	except socket.timeout as e:
        	print(e)
    
    	self.dhcps.close()
    	sys.exit(os.EX_OK)
   	
    def getServerIdentifier(self):
	_sid = self.DHCPServerIdentifier
	return _sid
