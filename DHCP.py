#!/usr/bin/python
import sys
sys.path.append('lib/') # this is where your python file exists

import DHClient as DHCP
import argparse
if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--client-ip', help='must be in the format xxx.yyy.zzz.aaa', required=True,action="store", dest="client_ip",type=str)
    parser.add_argument('--mac', help = 'must be in the format 00:26:9e:04:1e:9b', required=True, action="store", type=str)
    parser.add_argument('--dhcp-broadcast-ip', help = 'must be in the dhcp broadcast', required=True, action="store", type=str)
    args = parser.parse_args()
    dhcp = DHCP.DHClient(args.dhcp_broadcast_ip)	
    msg = dhcp.SendPacket( args.client_ip, args.mac )
    print msg
