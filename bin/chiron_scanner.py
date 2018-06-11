#!/usr/bin/python
import argparse
import Queue
import time
import re
import ctypes
import logging
import sys
import os
import multiprocessing
import random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	#supress Scapy warnings`
import scapy 
sys.path.append('../lib')
import sniffer_process
import ipaddr
import scanners
import create_layer4
import create_extension_headers_chain 
import checkip
import fileio 
import results
import auxiliary_functions
import definitions
import sniffer_process
import checkings
sys.setrecursionlimit(30000) #Required if you want to use too many embedded fragmented Fragmentations 

#packets_list={}
class Worker() :
		neighbor_solicitation_cache={}
		dns_resolution_cache={}
		#lock = threading.Lock()
		def __init__(self, values,source_ip,mac_source,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,gw_mac,queue, IPv6_scope_defined,packets_sent_list,tid) :
			#print "Worker initalisation"
			self.queue = queue
			self.tid = tid
			self.values = values
			self.source_ip=source_ip
			self.mac_source=mac_source
			self.list_of_next_headers=list_of_next_headers
			self.list_of_offsets=list_of_offsets
			self.list_of_fragment_lengths=list_of_fragment_lengths
			self.list_of_fragment_m_bits=list_of_fragment_m_bits
			self.gw_mac=gw_mac
			self.IPv6_scope_defined=IPv6_scope_defined
			self.packets_sent_list=packets_sent_list
			while True :
				dest = 0
				try:
					myworks = self.queue.get(timeout=1)
					dest = myworks[0]
					destports = myworks[1]
				except 	Queue.Empty :
					print "Worker %d exiting." % (self.tid)
					return
				targets=[]
				###CHECK THE VALIDITY OF THE IP DESTINATION ADDRESSES###
				resolved_ipv6_address=""
				if checkip.is_valid_host(dest):
					if self.dns_resolution_cache.get(dest):
						dest=self.dns_resolution_cache.get(dest)
					else:
						resolved_ipv6_address=scanners.dns_resolve_ipv6_addr(self.source_ip,dest, self.values.dns_server, self.gw_mac,self.values.interface)
						if resolved_ipv6_address:
							resolved=resolved_ipv6_address[0]#get and check just the first address, alternative option below
							print resolved, "is the IPv6 address of the host",dest
							self.dns_resolution_cache[dest]=resolved
							dest=resolved
				if self.IPv6_scope_defined==True or checkip.is_valid_ipv6(dest):  #No reason to check for the validity of an address if a scope has been defined
					addr6 = ipaddr.IPAddress(dest)
					myaddr=addr6.exploded
					if myaddr[0:2]=="ff":
						if int(myaddr[2]) >= 0 and int(myaddr[2]) < 8:
							ether_dst="33:33:"+myaddr[30:32]+":"+myaddr[32:37]+":"+myaddr[37:39]
					else:
						if self.values.target_mac:
							ether_dst=self.values.target_mac
						elif self.neighbor_solicitation_cache.get(dest):
							ether_dst=self.neighbor_solicitation_cache.get(dest)
						else:
							ether_dst=auxiliary_functions.find_single_mac(self.source_ip, dest, self.values.interface)
							#USE THE DEFAULT GATEWAY#
							if not ether_dst:
								if self.gw_mac:
									ether_dst=self.gw_mac
							self.neighbor_solicitation_cache[dest]=ether_dst
							if not ether_dst:
								print dest, "not found"
					if ether_dst:
						if self.values.nsol:
							print "IPv6 address ",dest, " has MAC adddress ", ether_dst
						s = scapy.config.conf.L2socket(iface=values.interface) # Open Socket Once
						unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,int(values.hoplimit),values.lEu,int(values.size_of_extheaders),values.fuzz)
						fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value=create_extension_headers_chain.create_fragmentable_part(values.lEf,int(values.size_of_extheaders),values.fuzz)
						if self.values.pmtu:
							if int(self.values.dmtu) > 1500:
								print "Your MTU value is",self.values.dmtu,"bytes, which is bigger than the Ethernet MTU (1500). Exiting..."
							else:
								scanners.path_mtu_discovery(self.source_ip,dest,ether_dst,self.values.interface,self.values.dmtu)
						elif (self.values.pn or self.values.sS or self.values.sX or self.values.sR or self.values.sF or self.values.sA or self.values.sN or self.values.sU or self.values.rh0):  
							layer4_and_payload=None
							if self.values.pn:
								layer4_and_payload=create_layer4.icmpv6(self.values.icmpv6_type,self.values.icmpv6_code,self.values.l4_data)
							elif self.values.sS:
								layer4_and_payload=create_layer4.tcp_packet(destports, "S", self.values.l4_data)
							elif self.values.sX:
								layer4_and_payload=create_layer4.tcp_packet(destports, "FPU",self.values.l4_data)
							elif self.values.sR:
								layer4_and_payload=create_layer4.tcp_packet(destports, "R",self.values.l4_data)
							elif self.values.sF:
								layer4_and_payload=create_layer4.tcp_packet(destports, "F",self.values.l4_data)
							elif self.values.sA:
								layer4_and_payload=create_layer4.tcp_packet(destports, "A",self.values.l4_data)
							elif self.values.sN:
								layer4_and_payload=create_layer4.tcp_packet(destports, "",self.values.l4_data)
							elif self.values.sU:
								layer4_and_payload=create_layer4.udp_packet(destports,self.values.l4_data)
							elif self.values.rh0:
								layer4_and_payload=create_layer4.type_0_routing_header([self.source_ip],self.values.layer4,self.values.l4_data,destports)
							packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
						elif self.values.tr_gen:
                                                        packets_list={}
							if self.values.layer4=="tcp":
							    if destports==-1:
								destports=80
                                                            print "Traceroute using TCP",destports
							    for hop_limit in range(self.values.minttl,self.values.maxttl+1):
							        source_port=random.randrange(1,65535,1)
							        while packets_list.has_key(source_port):
								    source_port=random.randrange(1,65535,1)
                                                                packets_list[source_port]=(hop_limit,dest)
							        layer4_and_payload=create_layer4.tcp_packet_id(destports,"S",self.values.l4_data,source_port)
						                unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,hop_limit,values.lEu,int(values.size_of_extheaders),values.fuzz)
							        packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							        create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
                                                            packets_sent_list.put(packets_list)
							elif self.values.layer4=="udp":
							    if destports==-1:
								destports=53
                                                            print "Traceroute using UDP",destports
							    for hop_limit in range(self.values.minttl,self.values.maxttl+1):
							        source_port=random.randrange(1,65535,1)
								while packets_list.has_key(source_port):
								    source_port=random.randrange(1,65535,1)
								packets_list[source_port]=(hop_limit,dest)
								layer4_and_payload=create_layer4.udp_packet_id(destports,self.values.l4_data,source_port)
						                unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,hop_limit,values.lEu,int(values.size_of_extheaders),values.fuzz)
							        packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							        create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
                                                            packets_sent_list.put(packets_list)
							else: #default layer4=="icmpv6":
                                                            print "Traceroute using ICMPv6",dest
							    for hop_limit in range(self.values.minttl,self.values.maxttl+1):
							        icmpid=random.randrange(1,65535,1)  #generate a random ICMPv6 id
								while packets_list.has_key(icmpid):
								    icmpid=random.randrange(1,65535,1)  #generate a random ICMPv6 id
								packets_list[icmpid]=(hop_limit,dest)
							        layer4_and_payload=create_layer4.icmpv6_id(self.values.l4_data,icmpid)
						                unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,hop_limit,values.lEu,int(values.size_of_extheaders),values.fuzz)
							        packets=create_extension_headers_chain.create_datagram(mac_source,ether_dst,int(values.number_of_fragments),list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,values.fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4_and_payload)
							        create_extension_headers_chain.send_packets(s,packets,values.flood,values.delay)
                                                            packets_sent_list.put(packets_list)
				else:
					if checkip.is_valid_host(dest):
						res_str=dest+ " could not be resolved"
					else:
						res_str=dest+ " is not a valid IPv6 address"
					self.results.append(res_str)
				self.queue.task_done()
#END OF class Worker()#

################ MAIN FUNCTION WILL FOLLOW #######################################
def main():
	#LET'S PARSE THE ARGUMENTS FIRST
	parser = argparse.ArgumentParser(version='0.8',description='An IPv6 port/network scanner. It can be combined with other modules of the framework.')
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
	parser.add_argument('-of', '--output_file', action="store", dest="output_file", help="the filename where the results will be stored.")
	parser.add_argument('-dns','--dns_resolve', action="store", dest="dns", default="", help="Resolve a give hostname to its IPv6 address (if any). You can use a comma-separated list")
	parser.add_argument('-dns-server','--dns_server', action="store", dest="dns_server", default="2001:470:20::2", help="the DNS server to use to resolve the hostnames to IPv6 address")
	parser.add_argument('-nsol','--neighbor_solicitation', action="store_true", dest="nsol", default=False, help="Display neighbor solicitation results (IPv6 vs MAC addresses). Default: False")
	parser.add_argument('-pmtu','--path_mtu_disovery', action="store_true", dest="pmtu", default=False, help="perform path MTU discovery.")
	parser.add_argument('-mtu','--MTU', action="store", dest="dmtu", default=1500, help="The initial MTU to use for path MTU discovery.")
	parser.add_argument('-rec','--passive_local_reconnaisance', action="store_true", dest="rec", default=False, help="ATTACK 1: Collects passively Neighbor/Router Solicitation/Advertisement Messages. Creates a list of IPv6 addresses / MAC addresses and various other IPv6 related information")
	parser.add_argument('-mpn','--multicast_ping_scan', action="store_true", dest="mpn", default=False, help="perform a multicast link-local ping6 scan. Default operation if nothing else has been defined")
	parser.add_argument('-sn','--ping_scan', action="store_true", dest="pn", default=False, help="perform a ping6 scan.")
	parser.add_argument('-type','--icmpv6_type', action="store", dest="icmpv6_type", default=128, help="perform a ping6 scan.")
	parser.add_argument('-code','--icmpv6_code', action="store", dest="icmpv6_code", default=0, help="perform a ping6 scan.")
	parser.add_argument('-sS','--syn_scan', action="store_true", dest="sS", default=False, help="perform a SYN TCP scan (default)")
	parser.add_argument('-sA','--ack_scan', action="store_true", dest="sA", default=False, help="perform an ACK TCP scan")
	parser.add_argument('-sX','--xmas_scan', action="store_true", dest="sX", default=False, help="perform an XMAS TCP scan")
	parser.add_argument('-sR','--reset_scan', action="store_true", dest="sR", default=False, help="perform a RESET TCP scan")
	parser.add_argument('-sF','--fin_scan', action="store_true", dest="sF", default=False, help="perform a FIN TCP scan")
	parser.add_argument('-sN','--null_scan', action="store_true", dest="sN", default=False, help="perform a NULL TCP scan")
	parser.add_argument('-sU','--udp_scan', action="store_true", dest="sU", default=False, help="perform a UDP scan")
	parser.add_argument('-tr-gr','--traceroute-graph', action="store_true", dest="tr_gr", default=False, help="perform TCP traceroute and produce a graph")
	parser.add_argument('-tr','--traceroute', action="store_true", dest="tr_gen", default=False, help="perform generic traceroute (it can use ALL Chiron flexibilities)")
	parser.add_argument('-max_ttl','--maximum_ttl', action="store", dest="maxttl", default=25, help="maximum ttl for traceroute")
	parser.add_argument('-min_ttl','--minimum_ttl', action="store", dest="minttl", default=1, help="minimum ttl for traceroute")
	parser.add_argument('-lfE','--list_fragmented_Extension_Headers', action="store", dest="lEf", default=False, help="Define an arbitrary list of Extension Headers which will be included in the fragmentable part")
	parser.add_argument('-luE','--list_unfragmented_Extension_Headers', action="store", dest="lEu", default=False, help="Define an arbitrary list of Extension Headers which will be included in the unfragmentable part")
	parser.add_argument('-hoplimit','--Hop_Limit', action="store", dest="hoplimit", default=64, help="The Hop Limit value of the IPv6 Header. Default: 64")
	parser.add_argument('-nf','--no_of_fragments', action="store", dest="number_of_fragments", default=0, help="the number of fragments to send")
	parser.add_argument('-lnh','--list_of_next_headers', action="store", dest="list_of_next_headers", default=False, help="the list of next headers to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-lo','--list_of_offsets', action="store", dest="list_of_offsets", default=False, help="the list of offsets to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-ll','--list_of_fragment_lengths', action="store", dest="list_of_fragment_lengths", default=False, help="the list of fragment lengths to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-lm','--list_of_fragment_m_bits', action="store", dest="list_of_fragment_m_bits", default=False, help="the list of fragment M (More Fragments to Follow) bits to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-id','--fragment_id', action="store", dest="fragment_id", default=-1, help="Fragment Identification number to be used in Fragment Extension Headers durign fragmentation.")
	parser.add_argument('-seh','--size_of_extension_header', action="store", dest="size_of_extheaders", default=1, help="the size of the additional Extension Header (in octets of bytes)")
	parser.add_argument('-l4','--layer4', action="store", dest="layer4", default="icmpv6", help="the layer4 protocol")
	parser.add_argument('-l4_data','--layer4_payload', action="store", dest="l4_data", default="", help="the payload of layer4")
	parser.add_argument('-p','--destination_port', action="store", dest="destport", default=False, help="destination port of a TCP or UDP scan. If not defined, ports 1-1024 will be scanned")
	parser.add_argument('-stimeout','--sniffer_timeout', action="store", dest="sniffer_timeout", default=None, help="The timeout (in seconds) when the integrated sniffer (IF used) will exit automatically.")
	parser.add_argument('-threads','--number_of_threads', action="store", dest="no_of_threads", default=1, help="The number of threads to use (for multi-threaded operation).")
	parser.add_argument('-delay','--sending_delay', action="store", dest="delay", default=0, help="sending delay between two consecutive fragments")
	parser.add_argument('-rh0','--route-type-0', action="store_true", dest="rh0", default=False, help="detect support of Type 0 Routing Headers")
	parser.add_argument('-fl','--flood', action="store_true", dest="flood", default=0, help="flood the targets")
	parser.add_argument('-fuzz','--fuzzing', action="store_true", dest="fuzz", default=0, help="fuzz the undefined fields of the IPv6 Extension Headers")
	parser.add_argument('-flooding-interval','--interval-of-flooding', action="store", dest="flooding_interval", default=0.1, help="the interval between packets when flooding the targets")
	parser.add_argument('-ftimeout','--flooding_timeout', action="store", dest="flooding_timeout", default=200, help="The time (in seconds) to flood your target.")
	values = parser.parse_args()

	###LETS DO SOME CHECKS FIRST TO SEE IF WE CAN WORK###	
	if os.geteuid() != 0:
	      	print "You must be root to run this script."
	      	exit(1)  
	#Define the default behaviour: Multi-ping scan
	if (not values.rec) and (not values.pn) and (not values.pmtu) and (not values.mpn) and (not values.nsol) and (not values.sS) and (not values.sX) and (not values.sA) and (not values.sN) and (not values.sR) and (not values.sF) and (not values.sU) and (not values.tr_gr) and (not values.tr_gen) and (not values.rh0) and (not values.dns):
		values.mpn=True
	scapy.config.conf.verb=0

	#GET YOUR SOURCE IPV6 AND MAC ADDRESS
	mac_source=definitions.define_source_mac_address(values.mac_source,values.random_mac)
	source_ip,mac_source= definitions.define_source_ipv6_address(values.source,mac_source,values.interface,values.random_source,values.prefix)

	###START SNIFFING###
	q = multiprocessing.Queue()
	packets_sent_list = multiprocessing.Queue()
	pr=None
	if values.rec:	
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 1,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.mpn:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 5,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.pn:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 2,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.sS or values.sA or values.sX or values.sR or values.sF or values.sN:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 3,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.sU:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 4,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.tr_gen:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 6,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif values.rh0:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 7,q,values.sniffer_timeout,source_ip,values.dns_server,))
	elif not values.pmtu:
    		pr = multiprocessing.Process(target=sniffer_process.mySniffer, args=(values.interface, 0,q,values.sniffer_timeout,source_ip,values.dns_server,))

	if not values.pmtu: #IN THIS CASE SNIFFER IS NOT REQUIRED BECAUSE WE USE THE SEND/RECEIVE FUNCTIONS OF SCAPY
		pr.daemon = True
		pr.start()
		time.sleep(1)	#to make sure than sniffer has started before we proceed, otherwise you may miss some traffic

	###THE ATTACKS WILL FOLLOW NOW###
	if values.rec:
		try:
                        if values.sniffer_timeout:
                            timeout=float(values.sniffer_timeout)
                        else:
                            timeout=5
			time.sleep(timeout)
        	except KeyboardInterrupt:
                	print "\n\nExiting on user's request..."
			print_scanning_results(values,q,source_ip,[])
                	exit(1)
		print_scanning_results(values,q,source_ip,[])
	elif values.mpn:
		scanners.multi_ping_scanner(source_ip,values.interface,values.flood, values.flooding_interval)
                if values.sniffer_timeout:
                        timeout=float(values.sniffer_timeout)
                else:
                        timeout=3
                time.sleep(timeout)
	 	alive_results(q,source_ip,values.output_file)
	elif values.dns:
		ip_list,IPv6_scope_defined = definitions.define_destinations(values.dns_server,values.input_file,values.smart_scan,values.prefix,values.input_combinations)
		gw_mac = auxiliary_functions.get_gw_mac(values.gateway,values.interface,ip_list,source_ip) 
		#Check if DNS resolution is what it is asked for
		fqdn_list = values.dns.split(",")
		for f in fqdn_list:
			if checkip.is_valid_host(f):
				resolved_ipv6_address=scanners.dns_resolve_ipv6_addr(source_ip,f, values.dns_server,gw_mac,values.interface)
				if resolved_ipv6_address:
					print f,resolved_ipv6_address
			else:
				print "Not a valid Full Qualified Domain Name"
		exit(1)
	else: ###ATTACKS THAT REQUIRE THE DEFINITION OF DESTINATION(S)-TARGETS###
		ip_list,IPv6_scope_defined = definitions.define_destinations(values.destination,values.input_file,values.smart_scan,values.prefix,values.input_combinations)
		gw_mac = auxiliary_functions.get_gw_mac(values.gateway,values.interface,ip_list,source_ip) 
		#check if fragmentation parameters are OK
		list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers=checkings.check_fragmentation_parameters(values.list_of_fragment_lengths,values.list_of_offsets,values.list_of_fragment_m_bits,values.list_of_next_headers,values.number_of_fragments)

		###TRACEROUTE GRAPH
		if values.tr_gr:
			ans,unans=scapy.layers.inet6.traceroute6(ip_list)
			print ans.display()
			if values.destination:
				#filename="> ./"+values.destination+".svg"
				filename="./"+values.destination+".svg"
			else:
				filename="traceroure_graph_results_of_file"+values.input_file+".svg"
				filename=filename.replace('/', '.')
				filename=">./"+filename
			filename=filename.replace(':', '.')
			ans.graph(target=filename)
			print "Graph is saved at",filename.strip('>')
			#exit(1)
                else:
		    ###DEFINE THE DESTINATION PORTS
		    destports=""
		    if values.sS or values.sA or values.sX or values.sR or values.sF or values.sN or values.sU:
			if values.destport:
				portlist = []
				if values.destport.find('-')!=-1 : #if found
					ports=values.destport.split(',')
					for p in ports:
						if p.find('-')!=-1:
							portragne = p.split('-')
	        					for r in xrange(int(portragne[0]), int(portragne[1]) + 1):
								portlist.append(str(r))
						else:
							portlist.append(p)
					destports = ','.join(portlist)
				else:
					destports=values.destport
			else:
				if values.sS or values.sA or values.sX or values.sR or values.sF or values.sN:
					portlist=fileio.read_ports_to_scan("tcp")
				else:
					portlist=fileio.read_ports_to_scan("udp")
				if not portlist:
					portlist=[str(x) for x in range(1,1025)] 
				destports = ','.join(portlist)

		    ###LET'S DO THE JOB NOW
		    queue = Queue.Queue()
		    print "Let's start scanning"
		    print "Press Ctrl-C to terminate before finishing"
		    if not destports:
			destports="-1"
		    for d in ip_list:
			for p in destports.split(","):
				queue.put([str(d),int(p)])
		    for i in xrange(1, int(values.no_of_threads)+1):
			pr2 = multiprocessing.Process(target=Worker, args=(values,source_ip,mac_source,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,gw_mac,queue,IPv6_scope_defined,packets_sent_list,i,))
			pr2.daemon = True
			pr2.start()
                        print "Worker %d Created!"%i
			pr2.join()
                    print "Stop sniffing..."
                    time.sleep(2) #to ensure that we shall capture potential late responses. 
                    pr.terminate()
		    if pr:
                        complete_packets_list=[]
			try:
				pr.join()
                                #print "Stop sniffing..."
                                #pr.terminate()
			except KeyboardInterrupt:
    				print "Exiting on user's request..."
				print_scanning_results(values,q,source_ip,complete_packets_list)
    				exit(1)	
                        if values.tr_gen:
                            while not packets_sent_list.empty():
                                try:
                                    packets_list=packets_sent_list.get(timeout=2)
                                    complete_packets_list.append(packets_list)
                                except Empty:
                                    continue
                        else:
                            packets_list={}
			print_scanning_results(values,q,source_ip,complete_packets_list)

def print_scanning_results(values,q,source_ip,packets_sent_list):
	my_results=[]
	while not q.empty():
    		my_results.append(q.get())
	print "\n\nScanning Complete!"
	print "=================="
	if values.sS or values.sA or values.sX or values.sR or values.sF or values.sN:
		print "IPv6 address\t\t\t\tProtocol    Port\tFlags"
		print "-------------------------------------------"
	elif values.sU:
		print "IPv6 address\t\t\t\tProtocol    Port"
		print "-------------------------------------------"
	elif values.pn:
		print "IPv6 address\t\t\t\t\tProtocol\t\tID"
		print "-------------------------------------------"
	elif values.tr_gen:
		routes=results.traceroute_results(my_results,packets_sent_list)
		for p in routes.keys():
		    print "\n",p,routes.get(p)

	if not values.tr_gen:
		opened_tcp_list,final_results=results.print_results(my_results, source_ip)

	#Write the results to an output file, if required
	if values.output_file:
		f = open(values.output_file,'w')
		f.write("\n\nScanning Complete!")
		f.write("\n====================\n")
		if values.sS or values.sA or values.sX or values.sR or values.sF or values.sN:
			f.write("\nIPv6 address\t\t\t\tProtocol    Port\tFlags\n")
		elif values.sU:
			f.write("\nIPv6 address\t\t\t\tProtocol    Port\n")
		elif values.pn:
			f.write("\nIPv6 address\t\t\t\t\tProtocol\t\tID\n")
		elif values.tr_gen:
			f.write("\n")	
			routes=traceroute_results(my_results)
			for p in routes.keys():
				f.write("\n"+str(p)+str(routes.get(p))+"\n")	
		if not values.tr_gen:
			for r in final_results:
				f.write(str(r)+"\n")	
			if opened_tcp_list:
				f.write("\n\nOPENED TCP PORTS")
				f.write("\n---------------\n")
				for r in opened_tcp_list:
					f.write(str(r)+"\n")
		f.close()

def alive_results(q,source_ip,output_file):
	my_results=[]
	while not q.empty():
    		my_results.append(q.get())
	print "\nAlive systems around... MAC/Link-Local/Global"
	print "=============================================="
	alive_systems_around=results.make_eth_link_global_pairs(my_results)
	results.print_results(alive_systems_around, source_ip)
	if output_file:
		f = open(output_file,'w')
		f.write("\nAlive systems around... MAC/Link-Local/Global\n")	
		f.write("==============================================!\n")	
		final_results=results.unique(alive_systems_around, source_ip)
		for r in final_results[0]:
			f.write(str(r)+"\n")	
		f.close()

if __name__ == '__main__':
    main()
