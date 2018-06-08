#!/usr/bin/python
import sys
sys.path.append('../lib')
import definitions
import argparse
import checkings
import address_generators
import sniffer_process
import multiprocessing
import Queue
import time
import os
import re
import scapy
import ipaddr
import create_layer4
import create_extension_headers_chain 
import fileio
import checkip
import auxiliary_functions
import itertools
import results
import logging
import address_generators
import create_extension_headers_chain
import address_generators
import create_layer4
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	#supress Scapy warnings`
sys.setrecursionlimit(30000) #Required if you want to use more than 160 multicast address records in MLDv2 Report messages

def RAs_with_prefix_and_router_options(s,flood,no_prefix_info,prefixes,mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,delay):
	layer4_and_payload = scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=255,M=0,O=0)
	for i in range(int(no_prefix_info)):
		myprefix=prefixes.get(timeout=1)
		layer4_and_payload=layer4_and_payload/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen=64,prefix=myprefix, validlifetime=0xffffffffL, preferredlifetime=0xffffffffL, L=1, R=1, A=1)/scapy.layers.inet6.ICMPv6NDOptRouteInfo(plen = 64,prefix=myprefix, rtlifetime=0xffffffffL)
	packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    	create_extension_headers_chain.send_packets(s,packets,flood,delay)

def RAs_with_prefix_options(s,flood,no_prefix_info,prefixes,mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,delay):
	layer4_and_payload = scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=255,M=0,O=0)
	for i in range(int(no_prefix_info)):
		myprefix=prefixes.get(timeout=1)
		layer4_and_payload=layer4_and_payload/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen=64,prefix=myprefix, validlifetime=0xffffffffL, preferredlifetime=0xffffffffL, L=1, R=1, A=1)
	packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    	create_extension_headers_chain.send_packets(s,packets,flood,delay)

def RAs_with_router_options(s,flood,no_prefix_info,prefixes,mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,delay):
	layer4_and_payload = scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=255,M=0,O=0)
	for i in range(int(no_prefix_info)):
		myprefix=prefixes.get(timeout=1)
		layer4_and_payload=layer4_and_payload/scapy.layers.inet6.ICMPv6NDOptRouteInfo(plen = 64,prefix=myprefix,rtlifetime= 0xffffffffL)
	packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    	create_extension_headers_chain.send_packets(s,packets,flood,delay)

def RAs_with_prefix_and_router_options(s,flood,no_prefix_info,prefixes,mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,delay):
	layer4_and_payload = scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=255,M=0,O=0)
	for i in range(int(no_prefix_info)):
		myprefix=prefixes.get(timeout=1)
		layer4_and_payload=layer4_and_payload/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen=64,prefix=myprefix, validlifetime=0xffffffffL, preferredlifetime=0xffffffffL, L=1, R=1, A=1)/scapy.layers.inet6.ICMPv6NDOptRouteInfo(plen = 64,prefix=myprefix, rtlifetime=0xffffffffL)
	packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    	create_extension_headers_chain.send_packets(s,packets,flood,delay)

def RAs_with_prefix_options_cont(prefixes_queue,s,flood,no_prefix_info,prefixes,mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,delay):
	layer4_and_payload = scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=255,M=0,O=0)
	for i in range(int(no_prefix_info)):
		try:
			myprefix=prefixes.get(timeout=1)
		except 	Queue.Empty :
			return
		layer4_and_payload=layer4_and_payload/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen=64,prefix=myprefix, validlifetime=0xffffffffL, preferredlifetime=0xffffffffL, L=1, R=1, A=1)
	packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    	create_extension_headers_chain.send_packets(s,packets,flood,delay)

def create_random_prefixes(prefixes_queue):
	while True:
		prefixes_queue.put(scapy.layers.inet6.RandIP6("2001:db8:1:*")+"::")

def main():
	#LET'S PARSE THE ARGUMENTS FIRST
	parser = argparse.ArgumentParser(version='0.8',description='An IPv6 neighbor discovery packet tool with enhanced capabilities and flexibility.')
	parser.add_argument('-mrec','--mld-recon', action="store_true", dest="mld_recon", default=0, help="perform MLD Recon")
	parser.add_argument('-of', '--output_file', action="store", dest="output_file", help="the filename where the results will be stored.")
	parser.add_argument('interface',  action="store", help="the network interface to use.")
	parser.add_argument('-gw','--gateway', action="store", dest="gateway", help="a gateway to use (only if required).")
	parser.add_argument('-s', '--source',  action="store", dest="source", default=False, help="the IPv6 address of the sender (if you want to spoof it).")
	parser.add_argument('-rs', '--random-source',  action="store_true", dest="random_source", default=False, help="randomise the IPv6 address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-m', '--mac',  action="store", dest="mac_source", default=False, help="the mac address of the sender (if you want to spoof it).")
	parser.add_argument('-tm', '--target_mac',  action="store", dest="target_mac", default=False, help="the mac address of the target (if you want to define it to avoid Neighbor Solicitation).")
	parser.add_argument('-rm', '--random-mac',  action="store_true", dest="random_mac", default=False, help="randomise the MAC address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-iL', '--input_file', action="store", dest="input_file", help="the filename that includes the IPv6 address(es) of the target(s) - one per line")
	parser.add_argument('-d', '--destination', action="store", dest="destination", help="the IPv6 address(es) of the target(s) - comma separated.")
	parser.add_argument('-sM','--smart_scan', action="store_true", dest="smart_scan", default=False, help="perform a smart scan")
	parser.add_argument('-pr', '--prefix', action="store", dest="prefix", default="fe80::", help="the IPv6 network prefix to use. Example: fe80:224:54ff:feba::")
	parser.add_argument('-iC', '--input_combinations', action="store", dest="input_combinations", help="the filename where the combimations to use are stored")
	parser.add_argument('-dns-server','--dns_server', action="store", dest="dns_server", default="2001:470:20::2", help="the DNS server to use to resolve the hostnames to IPv6 address")
	parser.add_argument('-nsol','--display_neighbor_solicitation', action="store_true", dest="nsol", default=False, help="Display neighbor solicitation results (IPv6 vs MAC addresses). Default: False")
	parser.add_argument('-lfE','--list_fragmented_Extension_Headers', action="store", dest="lEf", default=False, help="Define an arbitrary list of Extension Headers which will be included in the fragmentable part")
	parser.add_argument('-luE','--list_unfragmented_Extension_Headers', action="store", dest="lEu", default=False, help="Define an arbitrary list of Extension Headers which will be included in the unfragmentable part")
	parser.add_argument('-hoplimit','--Hop_Limit', action="store", dest="hoplimit", default=False, help="The Hop Limit value of the IPv6 Header. Default: 255 (for MLD, default=1).")
	parser.add_argument('-nf','--no_of_fragments', action="store", dest="number_of_fragments", default=0, help="the number of fragments to send")
	parser.add_argument('-lnh','--list_of_next_headers', action="store", dest="list_of_next_headers", default=False, help="the list of next headers to be used in the Fragment Headers, comma_separated")
	parser.add_argument('-lo','--list_of_offsets', action="store", dest="list_of_offsets", default=False, help="the list of offsets to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-ll','--list_of_fragment_lengths', action="store", dest="list_of_fragment_lengths", default=False, help="the list of fragment lengths to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-lm','--list_of_fragment_m_bits', action="store", dest="list_of_fragment_m_bits", default=False, help="the list of fragment M (More Fragments to Follow) bits to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-id','--fragment_id', action="store", dest="fragment_id", default=-1, help="Fragment Identification number to be used in Fragment Extension Headers durign fragmentation.")
	parser.add_argument('-seh','--size_of_extension_header', action="store", dest="size_of_extheaders", default=1, help="the size of the additional Extension Header (in octets of bytes)")
	parser.add_argument('-l4','--layer4', action="store", dest="layer4", default="icmpv6", help="the layer4 protocol")
	parser.add_argument('-l4_data','--layer4_payload', action="store", dest="l4_data", default="", help="the payload of layer4")
	parser.add_argument('-stimeout','--sniffer_timeout', action="store", dest="sniffer_timeout", default=5, help="The timeout (in seconds) when the integrated sniffer (IF used) will exit automatically.")
	parser.add_argument('-threads','--number_of_threads', action="store", dest="no_of_threads", default=1, help="The number of threads to use (for multi-threaded operation).")
	parser.add_argument('-delay','--sending_delay', action="store", dest="delay", default=0, help="sending delay between two consecutive fragments")
	parser.add_argument('-ra','--router-advertisement', action="store_true", dest="ra", default=False, help="Send Router Advertisement (messages)")
	parser.add_argument('-rand_ra','--random-router-advertisements', action="store_true", dest="rra", default=False, help="Randomise the advertised prefixes")
	parser.add_argument('-rand_ra2','--random-router-advertisements2', action="store_true", dest="rra2", default=False, help="Randomise the advertised prefixes")
	parser.add_argument('-no_of_prefix_info','--number_of_prefix_info', action="store", dest="no_prefix_info", default=45, help="number of Prefix Information options in Router Advertisement messages")
	parser.add_argument('-rand_ri','--random-router-information', action="store_true", dest="rri", default=False, help="Randomise the advertised router information in Router Advertisements")
	parser.add_argument('-no_of_router_info','--number_of_router_info', action="store", dest="no_router_info", default=45, help="number of Router Information options in Router Advertisement messages")
	parser.add_argument('-rand_ra_ri','--random-prefix-router-information', action="store_true", dest="rra_rri", default=False, help="Randomise the advertised prefix and router information in Router Advertisements")
	parser.add_argument('-chlim','--current_hop_limit', action="store", dest="current_hop_limit", default=64, help="Advertised Current Hop Limit - can be between 0 and 255. Default: 64")
	parser.add_argument('-M','--managed_address_configuration', action="store_true", dest="managed_address_configuration", default=False, help="Managed Address Configuration Flag. Default: False")
	parser.add_argument('-O','--other_configuration', action="store_true", dest="other_configuration", default=False, help="Other Configuration Flag. Default: False")
	parser.add_argument('-res','--reserved', action="store", dest="reserved", default=0, help="Reserved field. Default Value: 0.")
	parser.add_argument('-r_time','--reachable_time', action="store", dest="reachable_time", default=0, help="reachable_time (in milliseconds) for Router Advertisement messages")
	parser.add_argument('-r_timer','--retrans_timer', action="store", dest="retrans_timer", default=0, help="retrans timer (in milliseconds) for Router Advertisement messages")
	parser.add_argument('-rl','--router-lifetime', action="store", dest="router_lifetime", default=9000, help="The Router Lifetime - in seconds - for the Router Advertisement message - can be between 0 and 65535")
	parser.add_argument('-rp','--router-priority', action="store", dest="router_priority", default=1, help="The Router Priority: 0: Medium 1: High 2: Reserved 3: Low")
	parser.add_argument('-pr-length', '--prefix-length', action="store", dest="prefix_length", default="64", help="the IPv6 prefix length to use")
	parser.add_argument('-rd','--router-redirect', action="store_true", dest="rd", default=False, help="Send Router Redirect (messages)")
	parser.add_argument('-da', '--destination-address', action="store", dest="destination_address", default=False, help="the IPv6 destination address to be used in an ICMPv6 Router Redirect message")
	parser.add_argument('-ta', '--target-address', action="store", dest="target_address", default=False, help="the IPv6 target address to be used in an ICMPv6 Router Redirect and ICMPv6 Neighbor Solicitation/Advertisement messages")
	parser.add_argument('-tmr', '--target-mac-address-for-RA', action="store", dest="target_mac_RA", default=False, help="the MAC target address to be used in an ICMPv6 Router Redirect and ICMPv6 Neighbor Solicitation / Advertisement messages")
	parser.add_argument('-rt', '--random-target',  action="store", dest="random_target", default=False, help="randomise the target IPv6 address to use as a Fake Router in an ICMPv6 Redirect message.")
	parser.add_argument('-big', '--packet-too-big',  action="store_true", dest="big", default=False, help="Send ICMPv6 Packet Too Big messages")
	parser.add_argument('-mtu','--MTU', action="store", dest="dmtu", default=False, help="The MTU value to use.")
	parser.add_argument('-neighsol','--neighbor_solicitation', action="store_true", dest="neighsol", default=False, help="Send neighbor solicitation messages. Default: False")
	parser.add_argument('-rsol','--router-solicitation', action="store_true", dest="rsol", default=False, help="Send Router Solicitation (messages)")
	parser.add_argument('-neighadv','--neighbor_advertisement', action="store_true", dest="neighadv", default=False, help="Send neighbor advertisement messages. Default: False")
	parser.add_argument('-mldv1q','--mldv1_query', action="store_true", dest="mldv1_query", default=False, help="Send MLDv1 Query. Default: False")
	parser.add_argument('-mldv1qm','--mldv1_query_multi', action="store_true", dest="mldv1_query_multi", default=False, help="Send MLDv1 Query with multiple addresses. Default: False")
	parser.add_argument('-mldv1r','--mldv1_report', action="store_true", dest="mldv1_report", default=False, help="Send MLDv1 Report. Default: False")
	parser.add_argument('-mldv1rm','--mldv1_report_multi', action="store_true", dest="mldv1_report_multi", default=False, help="Send MLDv1 Report with multiple addresses. Default: False")
	parser.add_argument('-mldv1d','--mldv1_done', action="store_true", dest="mldv1_done", default=False, help="Send MLDv1 Done. Default: False")
	parser.add_argument('-mldv1dm','--mldv1_done_multi', action="store_true", dest="mldv1_done_multi", default=False, help="Send MLDv1 Done with multiple addresses. Default: False")
	parser.add_argument('-code','--code', action="store", dest="code", default=0, help="The code for ICMPv6 messages (if you want to customise it.")
	parser.add_argument('-mldmrd','--maximum_response_delay', action="store", dest="mldmrd", default=10000, help="The Maximum Response Delay in MLD Query messages (in milliseconds).")
	parser.add_argument('-mul_addr','--multicast_address', action="store", dest="mlladdr", default="::", help="The multicast address (to be uses as parameter in MLD messages.")
	parser.add_argument('-ralert','--router_alert', action="store_true", dest="router_alert", default=False, help="Include Router Alert as a HopByHop Option. Default: False")
	parser.add_argument('-mldv2q','--mldv2_query', action="store_true", dest="mldv2_query", default=False, help="Send MLDv2 Query. Default: False")
	parser.add_argument('-mldv2qm','--mldv2_query_multi', action="store_true", dest="mldv2_query_multi", default=False, help="Send MLDv2 Query with multiple addresses. Default: False")
	parser.add_argument('-res2','--reserved2', action="store", dest="resv2", default=0, help="Second Reserved field (when applicable). Default Value: 0.")
	parser.add_argument('-srsp','--suppress_router_site_processing', action="store", dest="s", default=0, help="Suppress Router Site Processing. Default Value: 0.")
	parser.add_argument('-qrv','--querier_robustness_variable', action="store", dest="qrv", default=0, help="Querier's Robustness Variable. Default Value: 0.")
	parser.add_argument('-qqic','--queriers_query_interval_code', action="store", dest="qqic", default=0, help="Querier's Query Interval Code. Default Value: 0.")
	parser.add_argument('-no_of_sources','--number_of_sources', action="store", dest="number_of_sources", default=0, help="Number of Source Addresses in the Query. Default Value: 0.")
	parser.add_argument('-addresses','--unicast_addresses', action="store", dest="addresses", default=False, help="A (coma-separated) list of unicast addresses. Default Value: False.")
	parser.add_argument('-mldv2r','--mldv2_report', action="store_true", dest="mldv2_report", default=False, help="Send MLDv2 Report. Default: False")
	parser.add_argument('-mldv2rm','--mldv2_report_multi', action="store_true", dest="mldv2_report_multi", default=False, help="Send MLDv2 Report messages with multiple addresses. Default: False")
	parser.add_argument('-mldv2rmo','--mldv2_report_multi_in_one', action="store_true", dest="mldv2_report_multi_in_one", default=False, help="Send MLDv2 Report messages with multiple addresses. Default: False")
	parser.add_argument('-mldv2rms','--mldv2_report_multi_sources', action="store_true", dest="mldv2_report_multi_sources", default=False, help="Send MLDv2 Report messages with multiple addresses and multiple sources. Default: False")
	parser.add_argument('-no_of_mult_addr_recs','--number_of_multicast_address_records', action="store", dest="number_of_mult_addr_recs", default=False, help="Number of Multicast Address Records in the MLDv2 Report.")
	parser.add_argument('-lmar','--list_multicast_address_records', action="store", dest="lmar", default=False, help="Define an arbitrary list of Multicast Address Records to be included with MLDv2 Report messages")
	parser.add_argument('-r','--router_flag', action="store_true", dest="router_flag", default=False, help="Router Flag for ICMPv6 Neighbor Advertisement messages. Default: False")
	parser.add_argument('-sol','--solicited_flag', action="store_true", dest="solicited_flag", default=False, help="Solicited Flag for ICMPv6 Neighbor Advertisement messages. Default: False")
	parser.add_argument('-o','--override_flag', action="store_true", dest="override_flag", default=True, help="Override Flag for ICMPv6 Neighbor Advertisement messages. Default: True")
	parser.add_argument('-dhcpv6_sol','--dhcpv6-solicit', action="store_true", dest="dhcpv6_sol", default=False, help="Send DHCPv6 Solicit (messages)")
	parser.add_argument('-dhcpv6_ra','--dhcpv6-advertisement', action="store_true", dest="dhcpv6_ra", default=False, help="Send DHCPv6 Advertisement (messages)")
	parser.add_argument('-fl','--flood', action="store_true", dest="flood", default=0, help="flood the targets")
	parser.add_argument('-fuzz','--fuzzing', action="store_true", dest="fuzz", default=0, help="fuzz the undefined fields of the IPv6 Extension Headers")
	parser.add_argument('-flooding-interval','--interval-of-flooding', action="store", dest="flooding_interval", default=0.1, help="the interval between packets when flooding the targets")
	parser.add_argument('-ftimeout','--flooding_timeout', action="store", dest="flooding_timeout", default=10, help="The time (in seconds) to flood your target.")
	values = parser.parse_args()

	###LETS TO SOME CHECKS FIRST TO SEE IF WE CAN WORK###	
	if os.geteuid() != 0:
	      	print "You must be root to run this script."
	      	exit(1)  
	if ((not values.rri) and (not values.rra) and (not values.rra2) and (not values.rra_rri) and (not values.mld_recon) and (not values.mldv1_query) and (not values.mldv1_query_multi) and (not values.mldv2_query_multi) and (not values.mldv1_report) and (not values.mldv1_report_multi) and (not values.mldv1_done) and (not values.mldv1_done_multi) and (not values.mldv2_query) and (not values.mldv2_report_multi) and (not values.mldv2_report_multi_in_one)  and (not values.mldv2_report_multi_sources)  and (not values.mldv2_report) and  (not values.ra) and (not values.rsol) and (not values.rd) and (not values.big) and (not values.neighsol) and (not values.neighadv) and (not values.dhcpv6_ra) and (not values.dhcpv6_sol)):
		print "Please tell me what you want me to do"
		exit(0)
	scapy.config.conf.verb=0
	#scapy.layers.inet6.conf.verb=0

	#GET YOUR SOURCE IPV6 AND MAC ADDRESS
	mac_source=definitions.define_source_mac_address(values.mac_source,values.random_mac)

        if values.mld_recon:
		source_ip=auxiliary_functions.get_my_link_local_ip(values.interface)
		values.mldv1_query=True
		values.router_alert=True
	if values.rra or values.rra2 or values.rri or values.rra_rri or values.mldv1_query or values.mldv1_query_multi or values.mldv2_query or values.mldv2_query_multi or values.mldv2_report_multi or values.mldv2_report_multi_in_one or values.mldv2_report_multi_sources or values.mldv1_report or values.mldv1_report_multi or values.mldv1_done or values.mldv1_done_multi or values.mldv2_report:
		mladdresses=[]
		if values.addresses:
			mldaddresses=values.addresses.split(",")
			for p in values.addresses.split(","):
				mladdresses.append(p)
		if not values.destination:
			if values.mldv1_done or values.mldv1_done_multi:
				values.destination="ff02::2"
			elif values.mldv2_report or values.mldv2_report_multi  or values.mldv2_report_multi_in_one or values.mldv2_report_multi_sources:
				values.destination="ff02::16"
			else:
				values.destination="ff02::1"
		if not values.source:
			values.source=auxiliary_functions.get_my_link_local_ip(values.interface)
	if not values.hoplimit:
		if values.mldv1_query or values.mldv1_query_multi or values.mldv2_query_multi or values.mldv2_query or values.mldv2_report_multi or values.mldv2_report_multi_in_one or values.mldv2_report_multi_sources  or values.mldv1_report_multi or values.mldv1_report or values.mldv1_done or values.mldv1_done_multi or values.mldv2_report:
			values.hoplimit=1
		else:
			values.hoplimit=255
	if values.dhcpv6_sol:
		if not values.destination:
			values.destination="ff02::1:2"
	if values.rsol:
		if not values.destination:
			values.destination="ff02::2"	
	if values.ra:
		if not values.destination:
			values.destination="ff02::1"	

	source_ip,mac_source= definitions.define_source_ipv6_address(values.source,mac_source,values.interface,values.random_source,values.prefix)

	#check if fragmentation parameters are OK
	list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers=checkings.check_fragmentation_parameters(values.list_of_fragment_lengths,values.list_of_offsets,values.list_of_fragment_m_bits,values.list_of_next_headers,values.number_of_fragments)

	ip_list,IPv6_scope_defined = definitions.define_destinations(values.destination,values.input_file,values.smart_scan,values.prefix,values.input_combinations)

        ####GATEWAY FOR THE LOCAL LINK IS NOT NEEDED
        #if not values.target_mac:
	#	gw_mac = auxiliary_functions.get_gw_mac(values.gateway,values.interface,ip_list,source_ip)
	#else:
	gw_mac=values.target_mac

	###THE ATTACKS WILL FOLLOW NOW###
	##If router redirection, check for the parameters##
	if values.rd or values.neighsol or values.neighadv:
		my_target_mac=False
		if values.target_mac_RA:
			my_target_mac=values.target_mac_RA
			if re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", my_target_mac.lower()):
				print "Target MAC address to use: ",my_target_mac
			else:
				print my_target_mac, " is is a non valid MAC address"
				print "Acceptable format: xx:xx:xx:xx:xx:xx:xx:xx where x from 0 to f"
				exit(0)
		if values.target_address:
			target_address=values.target_address	
        		if not checkip.is_valid_ipv6(target_address):
				print "Target address",target_address, "is not a valid IPv6 address"
				print "Please, fix the errors and come back"
				exit(0)
			elif not my_target_mac:
				my_target_mac=auxiliary_functions.find_single_mac(auxiliary_functions.get_my_ip(values.interface), target_address, values.interface)#find the MAC of the target IP performing nsol
				print target_address,my_target_mac
			if not my_target_mac:
				#randomise it
				print "MAC address for the target IPv6 address",target_address,"has not been found"
				my_target_mac = address_generators.generate_random_mac()
				print "random mac address to use as target is", my_target_mac
		elif values.random_target:
			target_address=address_generators.generate_random_ipv6(values.prefix)
			if not my_target_mac:
				#randomise it
				my_target_mac = address_generators.generate_random_mac()
				print "random mac address to use as target", my_target_mac
		else:
			target_address=auxiliary_functions.get_my_ip(values.interface)
			if not my_target_mac:
				my_target_mac=scapy.layers.l2.get_if_hwaddr(values.interface)
		if values.destination_address:
			destination_address=values.destination_address
		else:
			destination_address="::"
		print "target address=",target_address," my target mac=",my_target_mac," destination address=",destination_address

	###LET'S DO THE JOB NOW
	print "Let's start"
	print "Press Ctrl-C to terminate before finishing"
	queue = multiprocessing.Queue()
	for d in ip_list:
		queue.put(str(d))

	neighbor_solicitation_cache={}
	dns_resolution_cache={}
	while True :
		dest = 0
		try:
			dest = queue.get(timeout=1)
		except 	Queue.Empty :
			return
		targets=[]
		###CHECK THE VALIDITY OF THE IP DESTINATION ADDRESSES###
		resolved_ipv6_address=""
		if checkip.is_valid_host(dest):
			if dns_resolution_cache.get(dest):
				dest=dns_resolution_cache.get(dest)
			else:
				resolved_ipv6_address=dns_resolve_ipv6_addr(source_ip,dest, values.dns_server, gw_mac,values.interface)
				if resolved_ipv6_address:
					resolved=resolved_ipv6_address[0]#get and check just the first address, alternative option below
					print resolved, "is the IPv6 address of the host",dest
					dns_resolution_cache[dest]=resolved
					dest=resolved
		if IPv6_scope_defined==True or checkip.is_valid_ipv6(dest):  #No reason to check for the validity of an address if a scope has been defined
			addr6 = ipaddr.IPAddress(dest)
			myaddr=addr6.exploded
			if not values.target_mac:
				if myaddr[0:2]=="ff":
					if int(myaddr[2]) >= 0 and int(myaddr[2]) < 8:
						ether_dst="33:33:"+myaddr[30:32]+":"+myaddr[32:37]+":"+myaddr[37:39]
				elif gw_mac:
					ether_dst=gw_mac
				elif neighbor_solicitation_cache.get(dest):
					ether_dst=neighbor_solicitation_cache.get(dest)
				else:
					ether_dst=auxiliary_functions.find_single_mac(source_ip, dest, values.interface)
					if not ether_dst:
						print "I need to use a gateway but a gateway was not found. Please define a gateway on your own"
						sys.exit(0)
					else:
						neighbor_solicitation_cache[dest]=ether_dst
				if not ether_dst:
					print dest, "not found"
					sys.exit(0)
			else:
				ether_dst=values.target_mac
			if ether_dst:
				pr = False
				if values.rsol:
					q = multiprocessing.Queue()
    					pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 1,q,float(values.sniffer_timeout),source_ip,values.dns_server,))
					pr.daemon = True
					pr.start()
					time.sleep(1)
				elif values.mld_recon:
					q = multiprocessing.Queue()
    					pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 8,q,float(values.sniffer_timeout),source_ip,values.dns_server,))
					pr.daemon = True
					pr.start()

				s = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
				unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,int(values.hoplimit),values.lEu,int(values.size_of_extheaders),values.fuzz)
				fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value=create_extension_headers_chain.create_fragmentable_part(values.lEf,int(values.size_of_extheaders),values.fuzz)

				if values.nsol:
					print "IPv6 address ",dest, " has MAC adddress ", ether_dst
				layer4_and_payload=None
				###FIRST, THE FUNCTIONALITIES THAT USE THEIR OWN send_packets ACTION
				if values.mldv1_query_multi:
					multicast_address_list=address_generators.generate_ranges(values.mlladdr)
					for p in multicast_address_list:
						layer4_and_payload=mldv1_query(int(values.code),int(values.mldmrd), values.reserved,p,values.l4_data,values.router_alert)
						packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
						create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				elif values.rra2:
					prefixes = multiprocessing.Queue()
					for i in range(int(values.no_prefix_info)*int(values.no_of_threads)):
						prefixes.put(scapy.layers.inet6.RandIP6("2001:db8:1:*")+"::")
					print "initial bunch of",int(values.no_prefix_info)*int(values.no_of_threads)," prefixes was created"
					myprocesses2=[]
					myprocesses=[]
					for i in range(2):
						myprocesses2.append(multiprocessing.Process(target=create_random_prefixes, args=(prefixes,)))
						myprocesses2[i].daemon = True
						myprocesses2[i].start()
						print myprocesses2[i]
					for i in range(2):
						print i
						myprocesses2[i].join()
					for j in range(int(values.no_of_threads)):
						s1 = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
    						myprocesses.append(multiprocessing.Process(target=RAs_with_prefix_options_cont, args=(prefixes,s1,values.flood,values.no_prefix_info,prefixes,mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,values.delay,)))
						print "Process",j,"started"
						myprocesses[j].daemon = True
						myprocesses[j].start()
					for j in range(int(values.no_of_threads)):
						myprocesses[j].join()
				elif values.rra:
					print "First, I will prepare",int(values.no_prefix_info),"prefixes"
					prefixes = multiprocessing.Queue()
					for i in range(int(values.no_prefix_info)*int(values.no_of_threads)):
						prefixes.put(str(scapy.layers.inet6.RandIP6("2001:db8:1:*"))+"::")
					print "prefix info prepared"
					myprocesses2=[]
					for j in range(int(values.no_of_threads)):
						s1 = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
    						myprocesses2.append(multiprocessing.Process(target=RAs_with_prefix_options, args=(s1,values.flood,values.no_prefix_info,prefixes,mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,values.delay,)))
						print "Process",j,"started"
						myprocesses2[j].daemon = True
						myprocesses2[j].start()
					for j in range(int(values.no_of_threads)):
						myprocesses2[j].join()
				elif values.rri:
					print "First, I will prepare",int(values.no_prefix_info),"router info"
					prefixes = multiprocessing.Queue()
					for i in range(int(values.no_prefix_info)*int(values.no_of_threads)):
						prefixes.put(scapy.layers.inet6.RandIP6("2001:db8:1:*")+"::")
					print "router info prepared"
					for j in range(int(values.no_of_threads)):
						s1 = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
    						myprocesses2=multiprocessing.Process(target=RAs_with_router_options, args=(s1,values.flood,values.no_prefix_info,prefixes,mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,values.delay,))
						print "Process",j,"started"
						myprocesses2.daemon = True
						myprocesses2.start()
					for j in range(int(values.no_of_threads)):
						myprocesses2.join()
				elif values.rra_rri:
					print "First, I will prepare",int(values.no_prefix_info),"prefix/router info"
					prefixes = multiprocessing.Queue()
					for i in range(int(values.no_prefix_info)*int(values.no_of_threads)):
						prefixes.put(scapy.layers.inet6.RandIP6("2001:db8:1:*")+"::")
					print "prefix/router info prepared"
					for j in range(int(values.no_of_threads)):
						s1 = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
    						myprocesses2=multiprocessing.Process(target=RAs_with_prefix_and_router_options, args=(s1,values.flood,values.no_prefix_info,prefixes,mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,values.delay,))
						print "Process",j,"started"
						myprocesses2.daemon = True
						myprocesses2.start()
					for j in range(int(values.no_of_threads)):
						myprocesses2.join()
				elif values.mldv1_report_multi:
					multicast_address_list=address_generators.generate_ranges(values.mlladdr)
					for p in multicast_address_list:
						layer4_and_payload=create_layer4.mldv1_report(int(values.code),int(values.mldmrd),values.reserved,p,values.l4_data,values.router_alert)
						packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
						create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				elif values.mldv1_done_multi:
					multicast_address_list=address_generators.generate_ranges(values.mlladdr)
					for p in multicast_address_list:
						layer4_and_payload=create_layer4.mldv1_done(int(values.code),int(values.mldmrd), values.reserved,p,values.l4_data,values.router_alert)
						packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
						create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				elif values.mldv2_query_multi:
					multicast_address_list=address_generators.generate_ranges(values.mlladdr)
					for p in multicast_address_list:
						layer4_and_payload=create_layer4.mldv2_query(int(values.code),int(values.mldmrd), int(values.reserved),p,values.l4_data,values.router_alert, int(values.resv2), int(values.s), int(values.qrv), int(values.qqic), int(values.number_of_sources), mladdresses)
						packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
						create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				elif values.mldv2_report_multi:
					if (values.lmar):
						temp_list_of_multicast_address_records=values.lmar.split(",")
						list_of_multicast_address_records=create_extension_headers_chain.identify_parameters(temp_list_of_multicast_address_records)
						complete_ml_list=[]
						for p in list_of_multicast_address_records:
							ml_list=[]
							if p[1].has_key('dst'):
								mldaddr=str(p[1]['dst'])
								mladdr_ranges=address_generators.generate_ranges(mldaddr)
								for ml in mladdr_ranges:
									new_multicast_address_record={}
									new_multicast_address_record.update(p[1])
									new_multicast_address_record.update({'dst':ml})
									ml_list.append(new_multicast_address_record)
							complete_ml_list.append(ml_list)
						for element in itertools.product(*complete_ml_list):
							final_list_of_multicast_address_records=[]
							for e in element:
								mylist=[]
								mylist.append('')
								mylist.append(e)
								final_list_of_multicast_address_records.append(mylist)
							layer4_and_payload=create_layer4.mldv2_report(int(values.reserved),int(values.resv2),values.number_of_mult_addr_recs,final_list_of_multicast_address_records,values.l4_data,values.router_alert)
							packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				elif values.mldv2_report_multi_sources:
					if (values.lmar):
						temp_list_of_multicast_address_records=values.lmar.split(",")
						list_of_multicast_address_records=create_extension_headers_chain.identify_parameters(temp_list_of_multicast_address_records)
						complete_ml_list=[]
						for p in list_of_multicast_address_records:
							ml_list=[]
							if p[1].has_key('dst'):
								mldaddr=str(p[1]['dst'])
								mladdr_ranges=address_generators.generate_ranges(mldaddr)
								for ml in mladdr_ranges:
									new_multicast_address_record={}
									new_multicast_address_record.update(p[1])
									new_multicast_address_record.update({'dst':ml})
									ml_list.append(new_multicast_address_record)
							complete_ml_list.append(ml_list)
						for element in itertools.product(*complete_ml_list):
							saddresses_range=element[0]['saddresses']
							saddresses_ranges=address_generators.generate_ranges(saddresses_range)
							final_saddresses=""
							for saddr in saddresses_ranges:
								final_saddresses=final_saddresses+str(saddr)+"-"
							final_saddresses = final_saddresses[:-1]
							element[0]['saddresses']=final_saddresses
							final_list_of_multicast_address_records=[]
							for e in element:
								mylist=[]
								mylist.append('')
								mylist.append(e)
								final_list_of_multicast_address_records.append(mylist)
							layer4_and_payload=create_layer4.mldv2_report(int(values.reserved),int(values.resv2),values.number_of_mult_addr_recs,final_list_of_multicast_address_records,values.l4_data,values.router_alert)
							packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
				###THEN, THE FUNCTIONALITIES THAT USE A COMMON send_packets ACTION
				else:
					if values.ra:
						layer4_and_payload=create_layer4.icmpv6_router_advertisement(mac_source,int(values.current_hop_limit),values.managed_address_configuration,values.other_configuration,int(values.reserved),int(values.router_lifetime),int(values.reachable_time),int(values.retrans_timer),values.prefix,int(values.prefix_length),int(values.router_priority),int(values.dmtu),values.interface)	
					elif values.rd:
						layer4_and_payload=create_layer4.icmpv6_router_redirect(ether_dst,target_address,destination_address,dest,values.interface)
					elif values.big:
						layer4_and_payload=create_layer4.icmpv6_packet_too_big(int(values.dmtu),dest,source_ip)	
					elif values.neighadv:
						layer4_and_payload=create_layer4.neighbor_advertisement(my_target_mac,target_address, values.router_flag, values.solicited_flag,values.override_flag,values.reserved)	
					elif values.dhcpv6_ra:
						layer4_and_payload=create_layer4.dhcpv6_advertisement(mac_source,values.interface)	
					elif values.dhcpv6_sol:
						layer4_and_payload=create_layer4.dhcpv6_solicit(mac_source,values.interface)	
					elif values.mldv1_query:
						layer4_and_payload=create_layer4.mldv1_query(int(values.code),int(values.mldmrd), values.reserved,values.mlladdr,values.l4_data,values.router_alert)	
					elif values.mldv1_report:
						layer4_and_payload=create_layer4.mldv1_report(int(values.code),int(values.mldmrd), values.reserved,values.mlladdr,values.l4_data,values.router_alert)	
					elif values.mldv1_done:
						layer4_and_payload=create_layer4.mldv1_done(int(values.code),int(values.mldmrd), values.reserved,values.mlladdr,values.l4_data,values.router_alert)	
					elif values.mldv2_query:
						layer4_and_payload=create_layer4.mldv2_query(int(values.code),int(values.mldmrd), int(values.reserved),values.mlladdr,values.l4_data,values.router_alert, int(values.resv2), int(values.s), int(values.qrv), int(values.qqic), int(values.number_of_sources), mladdresses)	
					elif values.mldv2_report:
						if (values.lmar):
							temp_list_of_multicast_address_records=values.lmar.split(",")
							list_of_multicast_address_records=create_extension_headers_chain.identify_parameters(temp_list_of_multicast_address_records)
						else:
							list_of_multicast_address_records=False
						layer4_and_payload=create_layer4.mldv2_report(int(values.reserved),int(values.resv2),values.number_of_mult_addr_recs,list_of_multicast_address_records,values.l4_data,values.router_alert)	
					elif values.mldv2_report_multi_in_one:
						if (values.lmar):
							temp_list_of_multicast_address_records=values.lmar.split(",")
							list_of_multicast_address_records=create_extension_headers_chain.identify_parameters(temp_list_of_multicast_address_records)
							complete_ml_list=[]
							for p in list_of_multicast_address_records:
								if p[1].has_key('dst'):
									mldaddr=str(p[1]['dst'])
									mladdr_ranges=address_generators.generate_ranges(mldaddr)
								for my_mladdr in mladdr_ranges:
									ml_list=[]
									ml_list.append('')
									new_multicast_address_record={}
									new_multicast_address_record.update({'dst':my_mladdr})
									if p[1].has_key('rtype'):	
										new_multicast_address_record.update({'rtype':str(p[1]['rtype'])})
									if p[1].has_key('no_of_sources'):	
										new_multicast_address_record.update({'no_of_sources':str(p[1]['no_of_sources'])})
									if p[1].has_key('saddresses'):	
										new_multicast_address_record.update({'saddresses':str(p[1]['saddresses'])})
									if p[1].has_key('auxdata'):	
										new_multicast_address_record.update({'auxdata':str(p[1]['auxdata'])})
									if p[1].has_key('auxdatalen'):	
										new_multicast_address_record.update({'auxdatalen':str(p[1]['auxdatalen'])})
									ml_list.append(new_multicast_address_record)
									complete_ml_list.append(ml_list)
							layer4_and_payload=create_layer4.mldv2_report(int(values.reserved),int(values.resv2),values.number_of_mult_addr_recs,complete_ml_list,values.l4_data,values.router_alert)	
					elif values.rsol:
						layer4_and_payload=create_layer4.icmpv6_router_solicitation(mac_source,values.reserved,values.interface)	
					if layer4_and_payload:
						packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
    						create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
					else:
						if checkip.is_valid_host(dest):
							res_str=dest+ " could not be resolved"
						else:
							res_str=dest+ " is not a valid IPv6 address"
					#If a process sniffer has started, to avoid exiting the parent process. 
					if pr:
						try:
							pr.join()
						except KeyboardInterrupt:
							print 'parent received ctrl-c'
							print "\nScanning Incomplete. Results up to now"
							print "======================================="
							myresults=[]
							while not q.empty():
    								myresults.append(q.get())
							results.print_results(myresults, source_ip)
							if values.output_file:
								f = open(values.output_file,'w')
								f.write("\nScanning Incomplete. Results up to now\n")	
								f.write("==================!\n")	
								final_results=unique(myresults, source_ip)
								for r in final_results:
									f.write(str(r)+"\n")	
								f.close()
							sys.exit(0)
						print "\nScanning Results"
						print "================\n"
						myresults=[]
						while not q.empty():
    							myresults.append(q.get())
						results.print_results(myresults, source_ip)
						if values.output_file:
							f = open(values.output_file,'w')
							f.write("\nScanning Results!\n")	
							f.write("==================!\n")	
							final_results=unique(myresults, source_ip)
							for r in final_results:
								f.write(str(r)+"\n")	
							f.close()

if __name__ == '__main__':
    main()

