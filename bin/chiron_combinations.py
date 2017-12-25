#!/usr/bin/python
import itertools
import sys
import os


#Observations of IPv6 Addresses
#David Malone <David.Malone@nuim.ie>
#Hamilton Institute, NUI Maynooth.

def perm(n,seq,filename):
	f=open(filename,'w')
	for p in itertools.product(seq, repeat=n):
		hex_part=""
		for element in p:
			hex_part = hex_part + ":" +element 
		f.write(hex_part+"\n")
	f.close()

def read_ipv6_hex_addresses(filename):
	f = open(filename, 'r')
	ipv6addresses=[]
	for line in f.readlines():
		ipv6address=line.strip('\r\n') 
		ipv6addresses.append(ipv6address)
	f.close()
	return ipv6addresses

def main():
	if len(sys.argv)==3:
		filename1=sys.argv[1]
		filename2=sys.argv[2]
		if not os.path.isfile(filename1):
			print '[-] ' + filename1 + 'does not exist'
			exit(0)
		elif not os.access(filename1, os.R_OK):
			print '[-] ' + filename1 + 'access is denied'
			exit(0)
		else:
			perm(4,read_ipv6_hex_addresses(filename1), filename2)
			exit(0)
	else:
		print "Please provide the file name where with the IPv6 hex words are stored AND the filename where the results will be stored"

if __name__ == '__main__':
	main()
