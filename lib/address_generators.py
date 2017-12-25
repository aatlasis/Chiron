#!/usr/bin/python
# Filename: address_generators.py
import random
version = '0.9'

#Given a range of IPv6 addresses, it generates a list of them.
def generate_ranges(vdestination):
	hex_parts= vdestination.split(":")
	ip_list=[]
	for hex_part in hex_parts:
		hex_list=[]
		if hex_part.find('-')!=-1: # found
			hex_numbers=hex_part.split("-")
			start = int(hex_numbers[0], 16)
			end = int(hex_numbers[1], 16)
			if start > end:
				print "in the specified hex range in your IPv6 addresses, you must define the smallest value first"
				exit(1)
			for i in xrange(start, end + 1):
    				#print format(i, 'X')
    				hex_list.append(format(i, 'x'))
			new_ip_list = []
			for ip in ip_list:
				for l in hex_list:
					new_ip_list.append(ip+":"+l)
			ip_list = new_ip_list
		else:
			if not ip_list:	
				ip_list.append(hex_part)
			else:	
				new_ip_list = []
				for ip in ip_list:
					new_ip_list.append(ip+":"+hex_part)
				ip_list = new_ip_list
	return ip_list

def generate_random_ipv6(ipv6_prefix):
	myprefix=ipv6_prefix.strip(":")
	subnets=myprefix.split(":")
	count=0
	for s in subnets:
		if s:
			count = count + 1
	M = 16**4
	rand_ipv6= myprefix+":" + ":".join(("%x" % random.randint(0, M) for i in range(8-count)))
	return rand_ipv6.strip(":")

def generate_random_mac():
	return ':'.join(map(lambda x: "%02x" % x, [ 0x00, 0x16, 0x3E, random.randint(0x00, 0x7F), random.randint(0x00, 0xFF), random.randint(0x00, 0xFF) ]))

version = '0.9'
# End of address_generators.py
