#!/usr/bin/python
import argparse
import Queue
import multiprocessing
import re
import os  #required for iptables
import platform  #required for os detection
import subprocess
import logging
import random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)	#supress Scapy warnings`
import scapy
import sys
sys.path.append('../lib')
import ipaddr
import sniffer_process
import definitions
import auxiliary_functions
import checkings
import checkip
import create_extension_headers_chain

used_tcp_id=[]

class PicklablePacket:
    """A container for scapy packets that can be pickled (in contrast
    to scapy packets themselves)."""
    def __init__(self, pkt):
        self.contents = str(pkt)
        self.time = pkt.time
    def __call__(self):
        """Get the original scapy packet."""
        pkt = scapy.layers.l2.Ether(self.contents)
        pkt.time = self.time
        return pkt

#REQUIRED When loopback interface is used. Check if we can get rid off it - Use a pseudo interface instead of loopback?
'''def check_if_double_tcp_packet_in_ipv4_loopback(source_port,destination_port, seq, ack):
	if [source_port,destination_port,seq,ack] in used_tcp_id:
		used_tcp_id.remove([source_port,destination_port,seq,ack])
		return False
	else: 
		used_tcp_id.append([source_port,destination_port,seq,ack])
		return True
'''
#Sniff in IPv6 Interface, send to IPv4
class IPv6_to_IPv4_Worker() :
	def __init__(self,ipv6filter,ipv4_receiver,ipv4_sender, interface):
        	self.ipv6filter = ipv6filter
		self.interface = interface
		print "Start IPv6 Sniffing: ",self.ipv6filter
		self.ipv4_receiver = ipv4_receiver
		self.ipv4_sender = ipv4_sender
		print "IPv6 to IPv4 Worker started!"
		self.tipid=random.randrange(0,65535,1)
        	scapy.sendrecv.sniff(iface=self.interface,filter=self.ipv6filter, prn=self.handler, store=0)
    	def handler(self,pkt):
		if pkt.haslayer(scapy.layers.inet.TCP):
			del(pkt[scapy.layers.inet.TCP].chksum)
			mypayload = pkt[scapy.layers.inet.TCP]
			self.tipid=self.tipid+1
			pkt = scapy.layers.inet.IP(src=self.ipv4_receiver,dst=self.ipv4_sender,proto=6, flags=2, id=self.tipid)/mypayload
			#print "TCP IPv4 packet to send:", pkt.sprintf("%IP.src% %IP.dst% payload length=%IP.len% id=%IP.id% proto=%IP.proto% source port=%TCP.sport% destination port=%TCP.dport% flags=%TCP.flags% seq=%TCP.seq% ack=%TCP.ack%")
		elif pkt.haslayer(scapy.layers.inet.UDP):
			del(pkt[scapy.layers.inet.UDP].chksum)
			mypayload = pkt[scapy.layers.inet.UDP]
			self.tipid=self.tipid+1
			pkt = scapy.layers.inet.IP(src=self.ipv4_receiver,dst=self.ipv4_sender,proto=6, flags=2, id=self.tipid)/mypayload
			#print "UDP IPv4 packet to send:", pkt.sprintf("%IP.src% %IP.dst% payload length=%IP.len% id=%IP.id% proto=%IP.proto% source port=%UDP.sport% destination port=%UDP.dport%")
		try: 
			scapy.sendrecv.send(pkt)
		except: 
			print "Error at packet: ", pkt.summary()

class IPv4Sniffer():
    def __init__ (self,queue,myfilter,interface):
	self.queue=queue
        self.myfilter = myfilter
        self.interface = interface
	print "Start IPv4 Sniffing: ",self.myfilter
        scapy.sendrecv.sniff(iface=self.interface,filter=self.myfilter, prn=self.handler, store=0)
    def handler(self,pkt):
	packet=PicklablePacket(pkt)
	self.queue.put(packet)

class IPv6Sender():
	def __init__(self,values,queue,tid,mac_source,source_ip,dest,ether_dst,interface,list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers,fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value,unfragmentable_part,size_of_unfragmentable_part,number_of_fragments):
		self.values = values
		self.queue = queue
		self.mac_source=mac_source
		self.source_ip=source_ip
		self.dest=dest
		self.ether_dst=ether_dst
		self.interface=interface
		self.list_of_fragment_lengths=list_of_fragment_lengths
		self.list_of_offsets=list_of_offsets
		self.list_of_fragment_m_bits=list_of_fragment_m_bits
		self.list_of_next_headers=list_of_next_headers
		self.fragmentable_extension_headers=fragmentable_extension_headers
		self.size_of_fragmentable_extension_headers=size_of_fragmentable_extension_headers
		self.first_next_header_value=first_next_header_value
		self.unfragmentable_part=unfragmentable_part
		self.size_of_unfragmentable_part=size_of_unfragmentable_part
		self.number_of_fragments=number_of_fragments
		self.tid = tid
		self.s = scapy.config.conf.L2socket(iface=self.interface) # Open Socket Once
		print "Worker %d started!" %self.tid
		self.tipid=random.randrange(0,65535,1)
		while True :
			try :
				pkt = self.queue.get(timeout=0.1)  #HOW DOES TIMEOUT AFFECT THE PERFORMANCE? 
				#print pkt
				packet=PicklablePacket.__call__(pkt)
				#print packet.show()
				self.Sender(packet)
				#self.queue.task_done()
			except 	Queue.Empty :
				continue	
    	def Sender(self,packets):
		if packets.haslayer(scapy.layers.inet.TCP):
			#if not check_if_double_tcp_packet_in_ipv4_loopback(packets[scapy.layers.inet.TCP].sport, packets[scapy.layers.inet.TCP].dport, packets[scapy.layers.inet.TCP].seq, packets[scapy.layers.inet.TCP].ack):
				#print "TCP IPv4 packet received:", packets.sprintf("%IP.src% %IP.dst% payload length=%IP.len% id=%IP.id% proto=%IP.proto% source port=%TCP.sport% destination port=%TCP.dport% flags=%TCP.flags% seq=%TCP.seq% ack=%TCP.ack%")
				del(packets[scapy.layers.inet.TCP].chksum)
				mypayload = packets[scapy.layers.inet.TCP]
				if mypayload['TCP'].flags==2:
					if self.values.l4_data:
						mypayload=mypayload/self.values.l4_data
				try:
					packets_to_send=create_extension_headers_chain.create_datagram(self.mac_source,self.ether_dst,int(self.number_of_fragments),self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.values.fragment_id,self.unfragmentable_part,self.size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers,mypayload)
					create_extension_headers_chain.send_packets(self.s,packets_to_send,0,self.values.delay)
					#print "IPv6 packet sent with payload ", mypayload.summary()
				except:
					print "the following packet was not sent (too long?):", packets.summary()
		elif packets.haslayer(scapy.layers.inet.UDP):
			#print "UDP IPv4 packet received:", packets.sprintf("%IP.src% %IP.dst% payload length=%IP.len% id=%IP.id% proto=%IP.proto% source port=%UDP.sport% destination port=%UDP.dport%")
			del(packets[scapy.layers.inet.UDP].chksum)
			mypayload = packets[scapy.layers.inet.UDP]
			try:
				packets_to_send=create_extension_headers_chain.create_datagram(self.mac_source,self.ether_dst,int(self.number_of_fragments),self.list_of_next_headers,self.list_of_offsets,self.list_of_fragment_lengths,self.list_of_fragment_m_bits,self.values.fragment_id,self.unfragmentable_part,self.size_of_unfragmentable_part,self.first_next_header_value,self.fragmentable_extension_headers,self.size_of_fragmentable_extension_headers,mypayload)
				create_extension_headers_chain.send_packets(s,packets_to_send,0,self.values.delay)
				#print "IPv6 packet sent with payload ", mypayload.display()
			except:
				print "the following packet was not sent (too long?):", packets.display()

def main():
	#LET'S PARSE THE ARGUMENTS FIRST
	parser = argparse.ArgumentParser(version='0.9',description='An IPv6 tool.')
	parser.add_argument('ipv6interface',  action="store", help="the IPv6 network interface to use.")
	parser.add_argument('ipv4interface',  action="store", help="the IPv4 network interface to use.")
	parser.add_argument('ipv4_sender',  action="store", help="the ipv4 address of the initial sender")
	parser.add_argument('ipv4_receiver',  action="store", help="the ipv4 address where the proxy listens to")
	parser.add_argument('-l4_data','--layer4_payload', action="store", dest="l4_data", default="", help="the payload of layer4")
	parser.add_argument('-gw','--gateway', action="store", dest="gateway", help="a gateway to use (only if required).")
	parser.add_argument('-s', '--source',  action="store", dest="source", default=False, help="the IPv6 address of the sender (if you want to spoof it).")
	parser.add_argument('-rs', '--random-source',  action="store_true", dest="random_source", default=False, help="randomise the IPv6 address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-m', '--mac',  action="store", dest="mac_source", default=False, help="the mac address of the sender (if you want to spoof it).")
	parser.add_argument('-tm', '--target_mac',  action="store", dest="target_mac", default=False, help="the mac address of the target (if you want to define it to avoid Neighbor Solicitation).")
	parser.add_argument('-rm', '--random-mac',  action="store_true", dest="random_mac", default=False, help="randomise the MAC address of the sender (if you want to spoof it randomly).")
	parser.add_argument('-d', '--destination', action="store", dest="destination", help="the IPv6 address of the target. Just one target, not a list as in the other modules of the framework. ")
	parser.add_argument('-dns-server','--dns_server', action="store", dest="dns_server", default="2001:470:20::2", help="the DNS server to use to resolve the hostnames to IPv6 address")
	parser.add_argument('-lfE','--list_fragmented_Extension_Headers', action="store", dest="lEf", default=False, help="Define an arbitrary list of Extension Headers which will be included in the fragmentable part")
	parser.add_argument('-luE','--list_unfragmented_Extension_Headers', action="store", dest="lEu", default=False, help="Define an arbitrary list of Extension Headers which will be included in the unfragmentable part")
	parser.add_argument('-hoplimit','--Hop_Limit', action="store", dest="hoplimit", default=255, help="The Hop Limit value of the IPv6 Header. Default: 255.")
	
	parser.add_argument('-nf','--no_of_fragments', action="store", dest="number_of_fragments", default=0, help="the number of fragments to send")
	parser.add_argument('-lnh','--list_of_next_headers', action="store", dest="list_of_next_headers", default=False, help="the list of next headers to be used in the Fragment Headers, comma_separated")
	parser.add_argument('-lo','--list_of_offsets', action="store", dest="list_of_offsets", default=False, help="the list of offsets to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-ll','--list_of_fragment_lengths', action="store", dest="list_of_fragment_lengths", default=False, help="the list of fragment lengths to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-lm','--list_of_fragment_m_bits', action="store", dest="list_of_fragment_m_bits", default=False, help="the list of fragment M (More Fragments to Follow) bits to be used in the Fragment Headers when fragmentation takes place, comma_separated (optional)")
	parser.add_argument('-id','--fragment_id', action="store", dest="fragment_id", default=-1, help="Fragment Identification number to be used in Fragment Extension Headers durign fragmentation.")
	parser.add_argument('-delay','--sending_delay', action="store", dest="delay", default=0, help="sending delay between two consecutive fragments")
	parser.add_argument('-seh','--size_of_extension_header', action="store", dest="size_of_extheaders", default=1, help="the size of the additional Extension Header (in octets of bytes)")
	parser.add_argument('-stimeout','--sniffer_timeout', action="store", dest="sniffer_timeout", default=60, help="The timeout (in seconds) when the integrated sniffer (IF used) will exit automatically.")
	parser.add_argument('-threads','--number_of_threads', action="store", dest="no_of_threads", default=10, help="The number of threads to use (for multi-threaded operation).")
	values = parser.parse_args()

	###LETS TO SOME CHECKS FIRST TO SEE IF WE CAN WORK###	
	if os.geteuid() != 0:
	      	print "You must be root to run this script."
	      	exit(1)  
	scapy.config.conf.verb=0
	scapy.config.conf.L3socket=scapy.supersocket.L3RawSocket

	#GET YOUR SOURCE IPV6 AND MAC ADDRESS
	mac_source=definitions.define_source_mac_address(values.mac_source,values.random_mac)
	source_ip,mac_source= definitions.define_source_ipv6_address(values.source,mac_source,values.ipv6interface,values.random_source,False)

	#DEFINE DESTINATIONS AND GATEWAY MAC
	ip_list,IPv6_scope_defined = definitions.define_destinations(values.destination,False,False,False,False)
	gw_mac = auxiliary_functions.get_gw_mac(values.gateway,values.ipv6interface,ip_list,source_ip) 

	dest=ip_list[0] #Use just the 1st address, if more than one is provided. No reason for many targets addresses in the proxy

	###CHECK THE VALIDITY OF THE IP DESTINATION ADDRESSES###
	###DO THESE CHECKS ONLY FOR THE CASES REQUIRED###
	resolved_ipv6_address=""
	if checkip.is_valid_host(dest):
		resolved_ipv6_address=dns_resolve_ipv6_addr(dest, values.dns_server)
		if resolved_ipv6_address:
			dest=resolved_ipv6_address[0]#get and check just the first address, alternative option below
	if checkip.is_valid_ipv6(dest):  
		if dest=="ff02::1":
			ether_dst="33:33:00:00:00:01"
		elif values.gateway:
			ether_dst=gw_mac
		elif values.target_mac:
			ether_dst=values.target_mac
		else:
			ether_dst=auxiliary_functions.find_single_mac(source_ip, dest, values.ipv6interface)
		if not ether_dst:
			p=scapy.layers.inet6.conf.route6.route("::/0")
			ether_dst=auxiliary_functions.find_single_mac(p[1], p[2], p[0])
		if not ether_dst:
			print dest, "not found"
			exit(0)
	
	if checkip.is_valid_host(dest):
		res_str=dest+ " could not be resolved"
	else:
		res_str=dest+ " is not a valid IPv6 address"

	#CONFIGURE IPTABLES
	if platform.system()=="Linux":
		#output = subprocess.check_output(['ps', '-A'])
		#if 'firewalld' in output:
    		#	print("firewalld is up an running!")
		subprocess.call(['ip6tables', '-I', 'OUTPUT', '1', '-p', 'icmpv6', '--icmpv6-type', 'destination-unreachable', '-s', source_ip, '-d', values.destination, '-j', 'DROP'])
		subprocess.call(['iptables', '-I', 'OUTPUT', '1', '--source', '127.0.0.3', '--destination', '127.0.0.1','-p', 'tcp', '--tcp-flags', 'RST', 'RST',  '-j', 'DROP'])
		subprocess.call(['ip6tables', '-I', 'OUTPUT', '1', '-p', 'tcp', '-s', source_ip, '-d', values.destination, '-j', 'DROP'])
	else:
		print "This is not a Linux system. You must configure the firewall on your own"

        #CREATE THE IPV6 HEADER CHAIN
	list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers=checkings.check_fragmentation_parameters(values.list_of_fragment_lengths,values.list_of_offsets,values.list_of_fragment_m_bits,values.list_of_next_headers,values.number_of_fragments)
	unfragmentable_part,size_of_unfragmentable_part=create_extension_headers_chain.create_unfragmentable_part(source_ip, dest,int(values.hoplimit),values.lEu,int(values.size_of_extheaders),0)
	fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value=create_extension_headers_chain.create_fragmentable_part(values.lEf,int(values.size_of_extheaders),0)
	list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers=checkings.check_fragmentation_parameters(values.list_of_fragment_lengths,values.list_of_offsets,values.list_of_fragment_m_bits,values.list_of_next_headers,values.number_of_fragments)

	myfilter="ip6 and src " + dest + " and dst " + source_ip #"src " + values.ipv4_sender + " and dst " + values.ipv4_receiver
    	pr=multiprocessing.Process(target=IPv6_to_IPv4_Worker, args=(myfilter,values.ipv4_receiver,values.ipv4_sender,values.ipv6interface,))
	pr.daemon=True
	pr.start()

	queueIPv4=multiprocessing.Queue()	
	myfilter ="src "+values.ipv4_sender+" and dst "+values.ipv4_receiver
    	pr2=multiprocessing.Process(target=IPv4Sniffer, args=(queueIPv4, myfilter,values.ipv4interface,))
	pr2.daemon = True
	pr2.start()

	IPv6SenderProcesses=[]
	for i in xrange(1, int(values.no_of_threads)+1):
		print "IPv6 Sender Process ",i
		IPv6SenderProcesses.append(multiprocessing.Process(target=IPv6Sender, args=(values,queueIPv4,i,mac_source,source_ip,dest,ether_dst,values.ipv6interface,list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers,fragmentable_extension_headers,size_of_fragmentable_extension_headers,first_next_header_value,unfragmentable_part,size_of_unfragmentable_part,values.number_of_fragments,)))
		IPv6SenderProcesses[i-1].daemon = True
		IPv6SenderProcesses[i-1].start()
	try:
		pr.join()
		pr2.join()
		for i in xrange(1, int(values.no_of_threads)+1) :
			IPv6SenderProcesses[i-1].join()
			print "Worker %d Created!"%i
	except KeyboardInterrupt:
		print 'Received Ctrl-C'
		#RECONFIGURE IPTABLES
		if platform.system()=="Linux":
			print "Reconfigure ip(6)tables to the old state"
			subprocess.call(['ip6tables', '-D', 'OUTPUT', '1'])
			subprocess.call(['iptables', '-D', 'OUTPUT', '1'])
			subprocess.call(['ip6tables', '-D', 'OUTPUT', '1'])
			print "DONE"
		exit(0)

if __name__ == '__main__':
    main()
