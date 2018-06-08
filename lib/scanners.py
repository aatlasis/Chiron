#!/usr/bin/python
# Filename: scanners.py
import auxiliary_functions
import checkip
import create_layer4
import scapy
import random
#from scapy.all import * 
#from create_layers import *
#from checkip import *
#from auxiliary_functions import *
version = '0.9'

def dns_resolve_ipv6_addr(source_ip,hostname, dns_server, mac_gw,interface):
	mymac = scapy.layers.l2.get_if_hwaddr(interface) #my MAC address	
	hostname_ipv6_address=[]
	if checkip.is_valid_ipv6(dns_server):
		#print "resolving using IPv6 DNS server",dns_server,"using gateway",mac_gw
		if mac_gw:
			p=scapy.sendrecv.srp1(scapy.layers.l2.Ether(src=mymac,dst=mac_gw)/scapy.layers.inet6.IPv6(src=source_ip,dst=dns_server)/scapy.layers.inet.UDP()/scapy.layers.dns.DNS(rd=1,qd=scapy.layers.dns.DNSQR(qtype='AAAA', qname=hostname)),timeout=10) 
		else:
			p=scapy.sendrecv.srp1(scapy.layers.l2.Ether(src=mymac)/scapy.layers.inet6.IPv6(src=source_ip,dst=dns_server)/scapy.layers.inet.UDP()/scapy.layers.dns.DNS(rd=1,qd=scapy.layers.dns.DNSQR(qtype='AAAA', qname=hostname)),timeout=10) 
	elif checkip.is_valid_ipv4(dns_server):
		if mac_gw:
			p=scapy.sendrecv.srp1(scapy.layers.l2.Ether(src=mymac,dst=mac_gw)/scapy.layers.inet.IP(dst=dns_server)/scapy.layers.inet.UDP()/scapy.layers.dns.DNS(rd=1,qd=scapy.layers.dns.DNSQR(qtype='AAAA', qname=hostname)),timeout=10) 
		else:
			p=scapy.sendrecv.srp1(scapy.layers.l2.Ether(src=mymac)/scapy.layers.inet.IP(dst=dns_server)/scapy.layers.inet.UDP()/scapy.layers.dns.DNS(rd=1,qd=scapy.layers.dns.DNSQR(qtype='AAAA', qname=hostname)),timeout=10) 
	else:
		print "Not a valid IP address has been provided for a DNS server"
		exit(0)
	try:
	    if (p['DNS'].rcode == 0):			#No error
			DNSBlocks = [ ]
			if (p['DNS'].ancount > 0):		#If we have at least one answer from the answer block, process it
				DNSBlocks.append(p[scapy.layers.dns.DNS].an)
			if (p['DNS'].arcount > 0):		#Likewise for the "additional" block
				DNSBlocks.append(p[scapy.layers.dns.DNS].ar)
			for OneAn in DNSBlocks:
				while isinstance(OneAn,scapy.layers.dns.DNSRR):		#Somewhat equivalent:	while not isinstance(an, NoPayload):
					if (OneAn.rclass == 1) and (OneAn.type == 28):		#"IN" class and "AAAA" answer
						hostname_ipv6_address.append(OneAn.rdata)
					#Move to the next DNS object in the "an" block
					OneAn = OneAn.payload
	    else:
        		sys.stderr.write("unable to lookup " + hostname+". ")
	    if not hostname_ipv6_address:
			print "I couldn't find an IPv6 address for",hostname
	    return hostname_ipv6_address
	except:
	    print "No response from dns server",dns_server
	    exit(0)

def multi_ping_scanner(source,interface, mytimeout, flood,flooding_interval):
	for ifaces in scapy.arch.linux.in6_getifaddr(): 	#in6_getifaddr()  #return a list of IPs - ifaces, etc
		if ifaces[2]==interface:
			#Simple Echo Request
			packet=scapy.layers.inet6.IPv6(src=ifaces[0],dst="ff02::1")/create_layer4.icmpv6(128,0,"")
			scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst="33:33:00:00:00:01")/packet,iface=interface, loop=flood,inter=flooding_interval)
			#Unsolicted Neighbor Advertisement
			packet=scapy.layers.inet6.IPv6(src=ifaces[0],dst="ff02::1")/scapy.layers.inet6.ICMPv6ND_NA(R=0,S=0,O=0, tgt=auxiliary_functions.get_my_ip(interface))
			scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst="33:33:00:00:00:01")/packet,iface=interface, loop=flood,inter=flooding_interval)
			#Unknown Option in an IPv6 Destination Option Extension Header
			packet=scapy.layers.inet6.IPv6(src=ifaces[0],dst="ff02::1")/scapy.layers.inet6.IPv6ExtHdrDestOpt(options=scapy.layers.inet6.HBHOptUnknown(otype=128,optdata='x'))/create_layer4.icmpv6(128,0,"")
			scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst="33:33:00:00:00:01")/packet,iface=interface, loop=flood,inter=flooding_interval)
			#Send an unknown (Fake) IPv6 Extension Header
			packet=scapy.layers.inet6.IPv6(src=ifaces[0],dst="ff02::1",nh=200,)/scapy.layers.inet6.IPv6ExtHdrDestOpt()/create_layer4.icmpv6(128,0,"")
			scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst="33:33:00:00:00:01")/packet,iface=interface, loop=flood,inter=flooding_interval)

def ping_scanner(source,destination,ether_dst,interface,icmp_payload):
	other_side=destination
	my_PATH_MTU=len(icmp_payload)+48
	packet=scapy.layers.inet6.IPv6(src=source,dst=destination)/create_layer4.icmpv6(128,0,icmp_payload)
	try:
		ans,unans=scapy.sendrecv.srp(scapy.layers.l2.Ether(dst=ether_dst)/packet,iface=interface,retry=2,timeout=5)
	except:
		print "An exception has occured. Exiting..."
	for s,r in ans:
		if r.payload.payload.type == 2:	#ICMPv6PacketTooBig
			res = r[IPv6].src,"ICMPv6 Packet Too Big",r.payload.payload.sprintf("MTU=%mtu%")
			#results.append(res)
			other_side=r[IPv6].src
			my_PATH_MTU=r.payload.payload.mtu
	return other_side,my_PATH_MTU
		
def path_mtu_discovery(source,destination,ether_addresses,interface,initial_path_mtu):
	print "Path MTU Discovery"
	print "------------------"
	sender=source
	while not sender==destination:
		icmp_payload="A"*(int(initial_path_mtu)-48)
		sender,initial_path_mtu = ping_scanner(source,destination,ether_addresses,interface,icmp_payload)
		print "sender=",sender,"PATH MTU =",initial_path_mtu
# End of scanners.py
