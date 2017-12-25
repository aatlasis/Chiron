#!/usr/bin/python
# Filename: definitions.py
import auxiliary_functions
import address_generators
import checkip
import re
import os
import scapy
import ipaddr
import fileio
version = '0.9'

###DEFINE THE SOURCE MAC ADDRESS###
def define_source_mac_address(vmac_source,vrandom_mac):
	mac_source=vmac_source
	if mac_source:
		if re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_source.lower()):
			print "Source MAC address to use: ",mac_source
		else:
			print mac_source, " is is a non valid MAC address"
			print "Acceptable format: xx:xx:xx:xx:xx:xx:xx:xx where x from 0 to f"
			exit(1)
	elif vrandom_mac:
		mac_source=address_generators.generate_random_mac()
	return mac_source
	
###DEFINE THE SOURCE IPV6 ADDRESS###
def define_source_ipv6_address(vsource,mac_source,vinterface,vrandom_source,vprefix):
	source_ip = False
	if vsource:#If spoofed
		source_ip = vsource
               	if not checkip.is_valid_ipv6(source_ip):
			print "Source ip",source_ip, "is not a valid IPv6 address"
			print "Please, fix the errors and come back"
			exit(0)
		elif not mac_source:
			mac_source=auxiliary_functions.find_single_mac(auxiliary_functions.get_my_ip(vinterface), source_ip, vinterface)#find the MAC of the spoofed source IP performing nsol
		if not mac_source:
			#randomise it
			print "MAC address for IPv6 address",source_ip,"has not been found"
			mac_source = address_generators.generate_random_mac()
			print "random mac address to use as source is", mac_source
	elif vrandom_source:
		source_ip=address_generators.generate_random_ipv6(vprefix)
		if not mac_source:
			#randomise it
			mac_source = address_generators.generate_random_mac()
			print "random mac address to use as source is", mac_source
	elif vinterface:
		source_ip = auxiliary_functions.get_my_ip(vinterface)
		if not mac_source:
			mac_source=scapy.layers.l2.get_if_hwaddr(vinterface)
	elif not source_ip:
		#source_ip=addr
		print "An available source IPv6 address does not exist. Please, define a source IPv6 address and try again."
		exit(0)
	print "The MAC address of your sender is:", mac_source
	print "The IPv6 address of your sender is:", source_ip
	print "The interface to use is", vinterface
	return source_ip,mac_source

#DEFINE YOUR TARGETS/DESTINATIONS
def define_destinations(vdestination,vinput_file,vsmart_scan,vprefix,vinput_combinations):
	#comma_separated_list=False
	IPv6_scope_defined=False
	if not (vdestination or vinput_file or vsmart_scan):
		print "You must define your destination(s)"
		exit(1)
	if vinput_file:
		if not os.path.isfile(vinput_file):
 			print '[-] ' + vinput_file + 'does not exist'
 			exit(1)
		elif not os.access(vinput_file, os.R_OK):
 			print '[-] ' + vinput_file + 'access is denied'
 			exit(1)
		else:
			ip_list=fileio.read_ipv6_addresses(vinput_file)
	elif vsmart_scan:
		if not vprefix:
			print "You must provide the IPv6 prefix (/64) to use for the smart scan"
			exit(1)
		elif not vinput_combinations:
			print "You must provide the input filename where the combinations to use for the smart scan are stored"
			exit(1)
		else:
			if not os.path.isfile(vinput_combinations):
 				print '[-] ' + vinput_file + 'does not exist'
 				exit(1)
 			elif not os.access(vinput_combinations, os.R_OK):
 				print '[-] ' + vinput_file + 'access is denied'
 				exit(1)
			else:
				print "The IPv6 subnet ",vprefix,"/64 will be scanned using smart combinations"
				print "Now let's read the file with the IPv6 addresses of the targets"
				ip_list=[]
				for l in fileio.read_ipv6_addresses(vinput_combinations):
					ip_list.append(vprefix+l)
				print "Finished reading"
	elif vdestination.find('/')!=-1: # found
		subnet = vdestination.split("/")
		if (int(subnet[1]) > 127 or int(subnet[1])<64):
			print "The subnet range can be from /64 to /127"
			exit(1)
		net6 = ipaddr.IPv6Network(vdestination)
		print "Number of Hosts/IPs to scan = ", net6.numhosts
		ip_list=list(net6.iterhosts())
		IPv6_scope_defined=True
	elif vdestination.find('-')!=-1: # found - WHATIF thereis a FQDN with a - in it, e.g. www.f-in.gr?
		print "ranges were entered"
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
	else:
		ip_list = vdestination.split(",")
		#comma_separated_list=False
	return ip_list,IPv6_scope_defined

version = '0.9'
# End of  auxiliary_functions.py
