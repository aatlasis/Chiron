#!/usr/bin/python
# Filename: create_layer4.py
import random
import scapy
import string
version = '0.9'
mymac=""

def icmpv6(itype,icode,payload):
	icmpid=random.randrange(1,65535,1)  #generate a random ICMPv6 id
	header=scapy.layers.inet6.ICMPv6EchoRequest(type=int(itype),code=int(icode),data=payload,id=icmpid)
	return header	

def icmpv6_id(payload,icmpid):
	header=scapy.layers.inet6.ICMPv6EchoRequest(data=payload,id=icmpid)
	return header	

def udp_packet_id(destport,layer4_data,source_port):
	if not layer4_data:
		if destport==53:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==7:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x0D\x0A\x0D\x0A")
		elif destport==111:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==123:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\xE3\x00\x04\xFA\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC5\x4F\x23\x4B\x71\xB1\x52\xF3")
		elif destport==137:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x80\xF0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
		elif destport==161:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x30\x3A\x02\x01\x03\x30\x0F\x02\x02\x4A\x69\x02\x03\x00\xFF\xE3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0E\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xA0\x0C\x02\x02\x37\xF0\x02\x01\x00\x02\x01\x00\x30\x00")
		elif destport==1434:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x02")
		elif destport==177:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x01\x00\x02\x00\x01\x00")
		elif destport==427:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x02\x01\x00\x006 \x00\x00\x00\x00\x00\x01\x00\x02en\x00\x00\x00\x15service:service-agent\x00\x07default\x00\x00\x00\x00")
		elif destport==500:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\xA4\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x98\x01\x01\x00\x04\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x03\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x00\x00\x00\x24\x04\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01")
		elif destport==520:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10")
		elif destport==626:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="SNQUERY: 127.0.0.1:AAAAAA:xsvr")
		elif destport==1604:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==1645 or destport==1812:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x01\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==2049:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA3\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==2302:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x02\xf1\x26\x01\x26\xf0\x90\xa6\xf0\x26\x57\x4e\xac\xa0\xec\xf8\x68\xe4\x8d\x21")
		elif destport==6481:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="[PROBE] 0000")
		elif destport==5351:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00")
		elif destport==5353:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01")
		elif destport==1080:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="Amanda 2.6 REQ HANDLE 000-00000000 SEQ 0\nSERVICE noop\n")
		elif destport==17185:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x55\x55\x55\x55\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x55\x13\x00\x00\x00\x30\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==27910 or destport==27911 or destport==27912 or destport==27913 or destport==27914:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\xff\xff\xff\xffstatus")
		elif destport==26000 or destport==26001 or destport==26001 or destport==26002 or destport==26003 or destport==26004 or destport==27960 or destport==27961 or destport==27962 or destport==27963 or destport==27964 or destport==30720 or destport==30721 or destport==30722 or destport==30723 or destport==30724 or destport==44400:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\xff\xff\xff\xffgetstatus")
		elif destport==64738:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x00\x00\x00\x00abcdefgh")
		elif destport==3784:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x01\xe7\xe5\x75\x31\xa3\x17\x0b\x21\xcf\xbf\x2b\x99\x4e\xdd\x19\xac\xde\x08\x5f\x8b\x24\x0a\x11\x19\xb6\x73\x6f\xad\x28\x13\xd2\x0a\xb9\x12\x75")
		elif destport==8767:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x002x\xba\x85\tTeamSpeak\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nWindows XP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00 \x00<\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08nickname\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		elif destport==9987:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/scapy.packet.Raw(load="\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02\x9d\x74\x8b\x45\xaa\x7b\xef\xb9\x9e\xfe\xad\x08\x19\xba\xcf\x41\xe0\x16\xa2\x32\x6c\xf3\xcf\xf4\x8e\x3c\x44\x83\xc8\x8d\x51\x45\x6f\x90\x95\x23\x3e\x00\x97\x2b\x1c\x71\xb2\x4e\xc0\x61\xf1\xd7\x6f\xc5\x7e\xf6\x48\x52\xbf\x82\x6a\xa2\x3b\x65\xaa\x18\x7a\x17\x38\xc3\x81\x27\xc3\x47\xfc\xa7\x35\xba\xfc\x0f\x9d\x9d\x72\x24\x9d\xfc\x02\x17\x6d\x6b\xb1\x2d\x72\xc6\xe3\x17\x1c\x95\xd9\x69\x99\x57\xce\xdd\xdf\x05\xdc\x03\x94\x56\x04\x3a\x14\xe5\xad\x9a\x2b\x14\x30\x3a\x23\xa3\x25\xad\xe8\xe6\x39\x8a\x85\x2a\xc6\xdf\xe5\x5d\x2d\xa0\x2f\x5d\x9c\xd7\x2b\x24\xfb\xb0\x9c\xc2\xba\x89\xb4\x1b\x17\xa2\xb6")
		else:
			header = scapy.layers.inet.UDP(sport=source_port, dport=destport)
	else:
		header = scapy.layers.inet.UDP(sport=source_port, dport=destport)/layer4_data
	return header

def udp_packet(destport,layer4_data):
	source_port=random.randrange(1024,65535,1)
        header=udp_packet_id(destport,layer4_data,source_port)
	return header

def tcp_packet(destport, tcp_flags, layer4_data):
	my_seq_number=random.randrange(0,2*65535,1)
	source_port=random.randrange(1024,65535,1)
	header = scapy.layers.inet.TCP(sport=source_port, dport=destport, seq=my_seq_number, flags=tcp_flags)/layer4_data
	return header

def tcp_packet_id(destport, tcp_flags, layer4_data,source_port):
	my_seq_number=random.randrange(0,2*65535,1)
	header = scapy.layers.inet.TCP(sport=source_port, dport=destport, seq=my_seq_number, flags=tcp_flags)/layer4_data
	return header

def type_0_routing_header(myaddresses,layer4,l4_data,destport):
	if layer4=="tcp":
		header=scapy.layers.inet6.IPv6ExtHdrRouting(type=0,addresses=myaddresses, segleft=len(myaddresses))/tcp_packet(int(destport), "S",l4_data)
	elif layer4=="udp":
		header=scapy.layers.inet6.IPv6ExtHdrRouting(type=0,addresses=myaddresses, segleft=len(myaddresses))/udp_packet(int(destport),l4_data)
	else:
		header=scapy.layers.inet6.IPv6ExtHdrRouting(type=0,addresses=myaddresses, segleft=len(myaddresses))/icmpv6(128,0,l4_data)
	return header

def icmpv6_router_advertisement(source_mac,current_hop_limit,managed_address_configuration,other_configuration,reserved_field,router_lifetime,reachable_time,retrans_timer,myprefix,myprefixlength,router_priority,mymtu,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	if not mymtu:
		header=scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=current_hop_limit,M=managed_address_configuration,O=other_configuration,res=int(reserved_field),routerlifetime=router_lifetime,prf=router_priority,reachabletime=reachable_time,retranstimer=retrans_timer)/scapy.layers.inet6.ICMPv6NDOptSrcLLAddr(lladdr=mymac)/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen = myprefixlength,prefix = myprefix, validlifetime= 0xffffffffL, preferredlifetime= 0xffffffffL, L=1, R=1, A=1)   #M=0, O=0 implies that there is no information available via DHCPv6
	else:
		header=scapy.layers.inet6.ICMPv6ND_RA(code=0,chlim=current_hop_limit,M=managed_address_configuration,O=other_configuration,res=int(reserved_field),routerlifetime=router_lifetime,prf=router_priority,reachabletime=reachable_time,retranstimer=retrans_timer)/scapy.layers.inet6.ICMPv6NDOptSrcLLAddr(lladdr=mymac)/scapy.layers.inet6.ICMPv6NDOptMTU(mtu=mymtu)/scapy.layers.inet6.ICMPv6NDOptPrefixInfo(prefixlen = myprefixlength,prefix = myprefix, validlifetime= 0xffffffffL, preferredlifetime= 0xffffffffL, L=1, R=1, A=1)   #M=0, O=0 implies that there is no information available via DHCPv6
	return header

def dhcpv6_advertisement(source_mac,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	header=scapy.layers.inet.UDP(sport=547,dport=546)/DHCP6_Advertise()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptDNSServers()
	return header

def dhcpv6_reply(source_mac,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	header=scapy.layers.inet.UDP(sport=547,dport=546)/DHCP6_Reply()
	return header

def dhcpv6_solicit_windows(source_mac,interface,transaction_id):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	if transaction_id:
		tr_id=transaction_id
	header=scapy.layers.inet.UDP(sport=546,dport=547)/DHCP6_Solicit(trid=tr_id)/DHCP6OptElapsedTime()/DHCP6OptClientId()/DHCP6OptIA_NA()/DHCP6OptClientFQDN()/DHCP6OptVendorClass()/DHCP6OptOptReq()
	return header

def dhcpv6_solicit_linux(source_mac,interface,transaction_id):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	if transaction_id:
		tr_id=transaction_id
	header=scapy.layers.inet.UDP(sport=546,dport=547)/DHCP6_Solicit(trid=tr_id)/DHCP6OptClientId()/DHCP6OptOptReq()/DHCP6OptElapsedTime()/DHCP6OptClientFQDN()/DHCP6OptIA_NA()
	return header

def dhcpv6_solicit(source_mac,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	sol = DHCP6_Solicit()
	rc = DHCP6OptRapidCommit()
	opreq = DHCP6OptOptReq()
	et= DHCP6OptElapsedTime()
	cid = DHCP6OptClientId()
	iana = DHCP6OptIA_NA()
	rc.optlen = 0
	opreq.optlen = 4
	iana.optlen = 12
	iana.T1 = 3600 
	iana.T2 = 5400
	#iana.iaid= 2729
	cid.optlen = 10
	random.seed()
	# Generating SOLICIT message id
	sol.trid = random.randint(0,16777215)
	# Generating DUID-LL
	cid.duid = ("00030001"+ str(EUI(source_mac)).replace("-","")).decode("hex")
	# Assembing the packet
	header = scapy.layers.inet.UDP(sport=546,dport=547)/sol/cid/opreq/et/iana
	return header

def dhcpv6_request(source_mac,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	header=scapy.layers.inet.UDP(sport=546,dport=547)/DHCP6_Request()/DHCP6OptElapsedTime()/DHCP6OptClientId()/DHCP6OptServerId()/DHCP6OptIA_NA()/DHCP6OptIAAddress()/DHCP6OptClientFQDN()/DHCP6OptVendorClass()/DHCP6OptOptReq()
	return header

def mldv1_report(mldcode,mldmrd,mldreserved,mldmladdr,layer4_data,router_alert):
	if router_alert:
		if layer4_data:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/layer4_data
		else:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	else:
		if layer4_data:
			header=scapy.layers.inet6.ICMPv6MLReport(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/layer4_data
		else:
			header=scapy.layers.inet6.ICMPv6MLReport(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	return header

def mldv2_report(mldres1,mldreserved,my_number_of_multicast_address_records,list_of_multicast_address_records,layer4_data,router_alert):
	number_of_multicast_address_records=0
	if list_of_multicast_address_records:
		for l in list_of_multicast_address_records:
			number_of_multicast_address_records=number_of_multicast_address_records+1
			if l[1].has_key('rtype'):
				mldrtype=int(l[1]['rtype'])
			else:
				mldrtype=4
			if l[1].has_key('auxdatalen'):
				mld_auxdatalen=int(l[1]['auxdatalen'])
			else:
				mld_auxdatalen=0
			if l[1].has_key('auxdata'):
				mld_auxdata=str(l[1]['auxdata'])
			else:
				mld_auxdata=''
			if l[1].has_key('no_of_sources'):
				mld_no_of_sources=int(l[1]['no_of_sources'])
			else:
				mld_no_of_sources=0
			if l[1].has_key('dst'):
				mldaddr=str(l[1]['dst'])
			else:
				mldaddr="::"
			if number_of_multicast_address_records==1:
				if l[1].has_key('saddresses'):
					mld_saddresses=l[1]['saddresses']
					mldsaddresses=[]
					mldsaddresses.append(mld_saddresses)
					mldsaddresses=mld_saddresses.split('-')
					p=scapy.layers.inet6.ICMPv6MLDMultAddrRec(rtype=mldrtype, auxdata_len=mld_auxdatalen, sources_number=mld_no_of_sources, dst=mldaddr, sources=mldsaddresses,auxdata=mld_auxdata)
				else:
					p=scapy.layers.inet6.ICMPv6MLDMultAddrRec(rtype=mldrtype, auxdata_len=mld_auxdatalen, sources_number=mld_no_of_sources, dst=mldaddr,auxdata=mld_auxdata)
			else:
				if l[1].has_key('saddresses'):
					mld_saddresses=l[1]['saddresses']
					mldsaddresses=[]
					mldsaddresses.append(mld_saddresses)
					mldsaddresses=mld_saddresses.split('-')
					p=p/scapy.layers.inet6.ICMPv6MLDMultAddrRec(rtype=mldrtype, auxdata_len=mld_auxdatalen, sources_number=mld_no_of_sources, dst=mldaddr, sources=mldsaddresses,auxdata=mld_auxdata)
				else:
					p=p/scapy.layers.inet6.ICMPv6MLDMultAddrRec(rtype=mldrtype, auxdata_len=mld_auxdatalen, sources_number=mld_no_of_sources, dst=mldaddr,auxdata=mld_auxdata)

	if my_number_of_multicast_address_records:
		number_of_multicast_address_records=int(my_number_of_multicast_address_records)	

	if list_of_multicast_address_records:
		if router_alert:
			if layer4_data:
				header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/p/scapy.packet.Raw(layer4_data)
			else:
				header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/p
		else:
			if layer4_data:
				header=scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/p/scapy.packet.Raw(layer4_data)
			else:
				header=scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/p
	else:
		if router_alert:
			if layer4_data:
				header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/scapy.packet.Raw(layer4_data)
			else:
				header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)
		else:
			if layer4_data:
				header=scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)/scapy.packet.Raw(layer4_data)
			else:
				header=scapy.layers.inet6.ICMPv6MLReport2(res=mldres1,reserved=mldreserved,records_number=number_of_multicast_address_records)
	return header

def mldv1_done(mldcode,mldmrd,mldreserved,mldmladdr,layer4_data,router_alert):
	if router_alert:
		if layer4_data:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLDone(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLDone(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	else:
		if layer4_data:
			header=scapy.layers.inet6.ICMPv6MLDone(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.ICMPv6MLDone(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	return header

def mldv1_query(mldcode,mldmrd,mldreserved,mldmladdr,layer4_data,router_alert):
	if router_alert:
		if layer4_data:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLQuery(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLQuery(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	else:
		if layer4_data:
			header=scapy.layers.inet6.ICMPv6MLQuery(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.ICMPv6MLQuery(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr)
	return header

def mldv2_query(mldcode,mldmrd,mldreserved,mldmladdr,layer4_data,router_alert, myresv, s_flag, myqrv, myqqic, number_of_sources, myaddresses):
	if router_alert:
		if layer4_data:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLQuery2(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr,Resv=myresv, S=s_flag, QRV=myqrv, QQIC=myqqic, sources_number=number_of_sources,sources=myaddresses)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.IPv6ExtHdrHopByHop(nh=58,options=scapy.layers.inet6.RouterAlert())/scapy.layers.inet6.ICMPv6MLQuery2(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr,Resv=myresv, S=s_flag, QRV=myqrv, QQIC=myqqic, sources_number=number_of_sources,sources=myaddresses)
	else:
		if layer4_data:
			header=scapy.layers.inet6.ICMPv6MLQuery2(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr,Resv=myresv, S=s_flag, QRV=myqrv, QQIC=myqqic, sources_number=number_of_sources,sources=myaddresses)/scapy.packet.Raw(layer4_data)
		else:
			header=scapy.layers.inet6.ICMPv6MLQuery2(code=mldcode,mrd=mldmrd,reserved=mldreserved,mladdr=mldmladdr,Resv=myresv, S=s_flag, QRV=myqrv, QQIC=myqqic, sources_number=number_of_sources,sources=myaddresses)
	return header

def icmpv6_router_solicitation(source_mac,reserved_field,interface):
	if source_mac:
		mymac=source_mac
	else:
		mymac=get_if_hwaddr(interface)
	header=scapy.layers.inet6.ICMPv6ND_RS(res=int(reserved_field))/scapy.layers.inet6.ICMPv6NDOptSrcLLAddr(lladdr=mymac)
	return header

def icmpv6_router_redirect(target_mac,target_address,destination_address,fake_originator,interface):
	payload=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
	header=scapy.layers.inet6.ICMPv6ND_Redirect(tgt=target_address,dst=destination_address)/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(lladdr=target_mac)/scapy.layers.inet6.ICMPv6NDOptRedirectedHdr(pkt=scapy.layers.inet6.IPv6(src=fake_originator,dst=destination_address)/icmpv6(128,0,payload))
	return header

def icmpv6_packet_too_big(mymtu,source,destination):
	if not mymtu:
		mymtu=1500
	length=mymtu-2*48
	payload=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(length))
	header=scapy.layers.inet6.ICMPv6PacketTooBig(mtu=mymtu)/scapy.layers.inet6.IPv6(src=source,dst=destination)/icmpv6(2,0,payload)
	return header

def neighbor_advertisement(target_mac,target_address, router_flag, solicited_flag,override_flag,reserved_field):
	header=scapy.layers.inet6.ICMPv6ND_NA(tgt=target_address, R=router_flag, S=solicited_flag, O=override_flag,res=int(reserved_field))/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(type=2,lladdr=target_mac)
	return header

def neighbor_solicitation(target_mac,target_address,reserved_field):
	header=scapy.layers.inet6.ICMPv6ND_NS(tgt=target_address, res=int(reserved_field))/scapy.layers.inet6.ICMPv6NDOptDstLLAddr(type=1,lladdr=target_mac)
	return header

version = '0.9'
# End of create_layer4.py
