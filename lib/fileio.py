#!/usr/bin/python
# Filename: fileio.py

import sys
import os

version = '0.8'

def read_ipv6_addresses(filename):
	f = open(filename, 'r')
	ipv6addresses=[]
	for line in f.readlines():
		ipv6address=line.strip('\r\n') 
		ipv6addresses.append(ipv6address)
	f.close()
	return ipv6addresses

def read_ports_to_scan(protocol):
	filename="../files/"+protocol+"_ports.txt"
	ports=[]
	if not os.path.isfile(filename):
		print '[-] ' + filename + ' does not exist'
		return ports
	elif not os.access(filename, os.R_OK):
		print '[-] ' + filename + ' access is denied'
		return ports
	else:
		f = open(filename, 'r')
		for line in f.readlines():
			myports=line.strip('\r\n') 
			ports.append(myports)
		f.close()
		return ports

def main():
	if len(sys.argv)==2:
		filename=sys.argv[1]
		if not os.path.isfile(filename):
			print '[-] ' + filename + ' does not exist'
			exit(0)
		elif not os.access(filename, os.R_OK):
			print '[-] ' + filename + ' access is denied'
			exit(0)
		else:
			read_ipv6_addresses(filename)
			exit(0)
	else:
		print "Please provide the file name where with the IPv6 addresses"

if __name__ == '__main__':
	main()
# End of fileio.py
