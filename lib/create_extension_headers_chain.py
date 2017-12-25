#!/usr/bin/python
# Filename: create_extension_headers_chain.py
import random
import scapy
import time
version = '0.9'
Ethernet_MTU=1500

def make_list_of_ext_headers(my_list):
	list_of_ext_headers=[]
	temp_list_of_ext_headers=my_list.split(",")
	for t in temp_list_of_ext_headers:
		if not t.find("X")==-1:
			product=t.split("X")
			factor=product[0]
			header=product[1]
			for times in range(int(factor)):
				list_of_ext_headers.append(header)	
		else:
			list_of_ext_headers.append(t)
	return list_of_ext_headers #its member of a list contains the header value and the header's parameters, if any, e.g., 44(offset=4,m=1) )

def analyse_inserted_parameters(parameters):
	parameters_dictionary={}
	splitted_parameters=parameters.split(';')
	for s in splitted_parameters:
		parameter=s.split('=')
		parameters_dictionary[parameter[0].strip()] = parameter[1].strip() #field: p[0], corresponding value: p[1]
	return parameters_dictionary 

def identify_parameters(headers): #headers is a list that contains the headers+paramters
	list_of_headers_plus_parameters=[]
	for header in headers:
		header_parameters=[]
		if header.find('(')!=-1 : # need at least a left parenthesis to distinguish from the header value
			parts=header.split('(',1) #There should be only one occurence of (
			header_value=parts[0]
			parameters=parts[1].strip(')')  #Right part should still have the right parenthesis
			myparameters=analyse_inserted_parameters(parameters)
			header_parameters.append(header_value)
			header_parameters.append(myparameters)
			list_of_headers_plus_parameters.append(header_parameters)
		else:
			header_parameters.append(header)
			header_parameters.append(None)
			list_of_headers_plus_parameters.append(header_parameters)
	return list_of_headers_plus_parameters #Returns a list of header_types,parameters where parameters is a dictionary

def create_header_chain(lEu,lEf):
	list_of_unfragmented_ext_headers=[]
	list_of_fragmented_ext_headers=[]
	if lEu:
		list_of_unfrag_ext_headers=make_list_of_ext_headers(lEu)
		list_of_unfragmented_ext_headers= identify_parameters(list_of_unfrag_ext_headers)
	if lEf:
		list_of_frag_ext_headers=make_list_of_ext_headers(lEf)
		list_of_fragmented_ext_headers=identify_parameters(list_of_frag_ext_headers)
	return list_of_unfragmented_ext_headers,list_of_fragmented_ext_headers

def add_extension_header(type_of_extension_headers, size_of_extheader, parameters, fuzzy):
	next_header = False
	if parameters:
		if parameters.has_key('nh'):
			next_header=int(parameters['nh'])
	if type_of_extension_headers==44:
		myid=random.randrange(1,4294967296,1)  #generate a random fragmentation id
		if fuzzy:
			extheader=fuzz(scapy.layers.inet6.IPv6ExtHdrFragment(id=myid))
		else:
			
			extheader=scapy.layers.inet6.IPv6ExtHdrFragment(id=myid)
		if parameters:
			if parameters.has_key('offset'):
				extheader.offset=int(parameters['offset'])
			if parameters.has_key('m'):
				extheader.m=int(parameters['m'])
			if parameters.has_key('id'):
				extheader.id=int(parameters['id'])
			if parameters.has_key('nh'):
				extheader.id=int(parameters['nh'])
			if parameters.has_key('res1'):
				extheader.res1=int(parameters['res1'])
			if parameters.has_key('res2'):
				extheader.res1=int(parameters['res2'])
			if next_header:
				extheader.nh = next_header
	elif type_of_extension_headers==41:
		if fuzzy:
			extheader=fuzz(scapy.layers.inet6.IPv6())
		else:
			extheader=scapy.layers.inet6.IPv6()
		if parameters:
			if parameters.has_key('src'):
				extheader.src=parameters['src'].strip('"')
			if parameters.has_key('dst'):
				extheader.dst=parameters['dst'].strip('"')
			if next_header:
				extheader.nh=next_header
	elif type_of_extension_headers==4:
		if fuzzy:
			extheader=fuzz(scapy.layers.inet.IP())
		else:
			extheader=scapy.layers.inet.IP()
		if parameters:
			if parameters.has_key('src'):
				extheader.src=str(parameters['src'])
			if parameters.has_key('dst'):
				extheader.dst=str(parameters['dst'])
			if next_header:
				extheader.nh=next_header
	elif type_of_extension_headers==0 or type_of_extension_headers==60:
		if type_of_extension_headers==0:		
			if fuzzy:
				extheader=fuzz(scapy.layers.inet6.IPv6ExtHdrHopByHop())
			elif not parameters:
				extheader=scapy.layers.inet6.IPv6ExtHdrHopByHop(options=scapy.layers.inet6.PadN(optdata='\101'*(size_of_extheader-1)*8))
			else:
				extheader=scapy.layers.inet6.IPv6ExtHdrHopByHop()
		else:		
			if fuzzy:
				extheader=fuzz(scapy.layers.inet6.IPv6ExtHdrDestOpt())
			elif not parameters:
				extheader=scapy.layers.inet6.IPv6ExtHdrDestOpt(options=scapy.layers.inet6.PadN(optdata='\101'*(size_of_extheader-1)*8))
			else:
				extheader=scapy.layers.inet6.IPv6ExtHdrDestOpt()
		if parameters:
			if next_header:
				extheader.nh=next_header
			if parameters.has_key('options'):
				if parameters['options']=="RouterAlert":
					extheader=scapy.layers.inet6.IPv6ExtHdrHopByHop(options=RouterAlert())
 				elif parameters['options']=="Jumbo":
                                        if parameters.has_key('jumboplen'):
                                                extheader=scapy.layers.inet6.IPv6ExtHdrHopByHop(options=[Jumbo(jumboplen=int(parameters['jumboplen']))])
                                        else:
                                                extheader=scapy.layers.inet6.IPv6ExtHdrHopByHop(options=[Jumbo()])
			else:		
				mykeys=parameters.keys()
				otypes=[]
				odata=[]
				for mykey in mykeys:
					if mykey[0:5]=='otype':
						otypes.append(mykey)
					elif mykey[0:5]=='odata':
						odata.append(mykey)
				for myotype in otypes:
					try:
						if odata[otypes.index(myotype)]:
							test = parameters[odata[otypes.index(myotype)]].strip('"')
							if test.find('\\x')!=-1:
								x = test.split("\\x")
								myodata=""
								for l in x:
									try:
										myodata = myodata+chr(int(l,16))
									except:
										continue
							else:
								myodata=test
							if otypes.index(myotype)==0:
								theoptions=scapy.layers.inet6.HBHOptUnknown(optdata=myodata,otype=int(parameters[myotype]))
							else:
								theoptions=theoptions/scapy.layers.inet6.HBHOptUnknown(optdata=myodata,otype=int(parameters[myotype]))
							extheader.options=scapy.layers.inet6.HBHOptUnknown(optdata=str(parameters[odata[otypes.index(myotype)]]),otype=int(parameters[myotype]))
						else:
							if otypes.index(myotype)==0:
								theoptions=scapy.layers.inet6.HBHOptUnknown(otype=int(parameters[myotype]))
							else:
								theoptions=theoptions/scapy.layers.inet6.HBHOptUnknown(otype=int(parameters[myotype]))
					except: 
							if otypes.index(myotype)==0:
								theoptions=scapy.layers.inet6.HBHOptUnknown(otype=int(parameters[myotype]))
							else:
								theoptions=theoptions/scapy.layers.inet6.HBHOptUnknown(otype=int(parameters[myotype]))
				if "theoptions" in globals():
					extheader.options=theoptions
	elif type_of_extension_headers==43:
		if fuzzy:
			extheader=fuzz(scapy.layers.inet6.IPv6ExtHdrRouting())
		else:
			extheader=scapy.layers.inet6.IPv6ExtHdrRouting()
		if parameters:
			if parameters.has_key('type'):
				extheader.type=int(parameters['type'])
			if parameters.has_key('reserved'):
				extheader.reserved=int(parameters['reserved'])
			if parameters.has_key('addresses'):
				myaddresses=[]
				alladdresses=parameters['addresses'].split("-")
				for a in alladdresses:
					myaddresses.append(a)
				extheader.addresses=myaddresses
			if parameters.has_key('segleft'):
				extheader.segleft=int(parameters['segleft'])
			elif parameters.has_key('addresses'):
				if myaddresses:
					extheader.segleft=len(myaddresses)
			if next_header:
				extheader.nh=next_header
	elif type_of_extension_headers==135:
		if fuzzy:
			extheader=fuzz(MIP6MH_HoT())
		else:
			extheader=MIP6MH_HoT()
		if next_header:
			extheader.nh=next_header
	else:	#adds a Fake IPv6 Extension Header
		if next_header:
			extheader=scapy.layers.inet6.IPv6ExtHdrFake(nh=next_header)
		else:
			extheader=scapy.layers.inet6.IPv6ExtHdrFake()
	return extheader

def frag_datagram(fragmentable_part, no_of_fragments, list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,next_header, fragment_id):
	datagram=[]
	myid=int(fragment_id)
	if myid<0 or myid>4294967296:
		myid=random.randrange(1,4294967296,1)  #generate a random fragmentation id
	if not list_of_fragment_lengths:
		if no_of_fragments>1 or no_of_fragments==1:
			size_of_fragments = (len(fragmentable_part))/(8*no_of_fragments) # divided by 8 to get octets of bytes
			for i in range(1, no_of_fragments):
				if list_of_fragment_m_bits:
					my_m_bit=int(list_of_fragment_m_bits[i-1])
				else:
					my_m_bit=1
				if list_of_offsets:
					myoffset=int(list_of_offsets[i-1])
				else:
					myoffset=(i-1)*size_of_fragments
				if list_of_next_headers:
					fragment=scapy.layers.inet6.IPv6ExtHdrFragment(offset=myoffset,m=my_m_bit,id=myid, nh=int(list_of_next_headers[i-1]))/fragmentable_part[(i-1)*size_of_fragments*8:i*size_of_fragments*8]
				else:
					fragment=scapy.layers.inet6.IPv6ExtHdrFragment(offset=myoffset,m=my_m_bit,id=myid, nh=next_header)/fragmentable_part[(i-1)*size_of_fragments*8:i*size_of_fragments*8]
				datagram.append(fragment)
			if list_of_fragment_m_bits:
				my_m_bit=int(list_of_fragment_m_bits[no_of_fragments-1])
			else:
				my_m_bit=0
			if list_of_offsets:
				myoffset=int(list_of_offsets[no_of_fragments-1])
			else:
				myoffset=(no_of_fragments-1)*size_of_fragments
			if list_of_next_headers:
				fragment=scapy.layers.inet6.IPv6ExtHdrFragment(offset=myoffset,m=my_m_bit,id=myid, nh=int(list_of_next_headers[no_of_fragments-1]))/fragmentable_part[(no_of_fragments-1)*size_of_fragments*8:]
			else:
				fragment=scapy.layers.inet6.IPv6ExtHdrFragment(offset=myoffset,m=my_m_bit,id=myid, nh=next_header)/fragmentable_part[(no_of_fragments-1)*size_of_fragments*8:]
			datagram.append(fragment)
			return datagram
		elif no_of_fragments==1:
			if list_of_next_headers:
				exheader=scapy.layers.inet6.IPv6ExtHdrFragment(offset=0,m=0,id=myid, nh=int(list_of_next_headers[0]))/fragmentable_part
			else:
				exheader=scapy.layers.inet6.IPv6ExtHdrFragment(offset=0,m=0,id=myid, nh=next_header)/fragmentable_part
			datagram.append(exheader)
			return datagram
		else:
			datagram.append(fragmentable_part)
			return datagram
	else:
		#Completely arbitrary fragmentation
		for i in range (0,int(len(list_of_fragment_lengths))):
			#print "packet/offset/length/m_bit/nh/id"
			#print i,int(list_of_offsets[i]),int(list_of_fragment_lengths[i]),int(list_of_fragment_m_bits[i]),int(list_of_next_headers[i]),myid
			fragment=scapy.layers.inet6.IPv6ExtHdrFragment(offset=int(list_of_offsets[i]),m=int(list_of_fragment_m_bits[i]),id=myid, nh=int(list_of_next_headers[i]))/fragmentable_part[int(list_of_offsets[i])*8:(int(list_of_offsets[i])+int(list_of_fragment_lengths[i]))*8]
			datagram.append(fragment)
		return datagram

def create_unfragmentable_part(source,destination,hoplimit,lEu,size_of_extension_headers,fuzz):
	list_of_unfragmented_extension_headers=[]
	if lEu:
		list_of_unfrag_ext_headers=make_list_of_ext_headers(lEu)
		list_of_unfragmented_extension_headers= identify_parameters(list_of_unfrag_ext_headers)
	IPv6_datagram=scapy.layers.inet6.IPv6(src=source,dst=destination,hlim=hoplimit)
	if list_of_unfragmented_extension_headers:
		for l in list_of_unfragmented_extension_headers:
			IPv6_datagram = IPv6_datagram/add_extension_header(int(l[0]), size_of_extension_headers, l[1], fuzz)
	unfragmentable_part=IPv6_datagram
	size_of_unfragmentable_part=len(unfragmentable_part)
	return unfragmentable_part,size_of_unfragmentable_part

def create_fragmentable_part(lEf,size_of_extension_headers,fuzz):
	list_of_fragmented_extension_headers=[]
	if lEf:
		list_of_frag_ext_headers=make_list_of_ext_headers(lEf)
		list_of_fragmented_extension_headers=identify_parameters(list_of_frag_ext_headers)
	fragmentable_part=None
	size_of_fragmentable_extension_headers=0
	if list_of_fragmented_extension_headers:
		first_next_header_value=int(list_of_fragmented_extension_headers[0][0])
		l=list_of_fragmented_extension_headers[0]
		fragmentable_part=add_extension_header(int(l[0]), size_of_extension_headers, l[1], fuzz)
		list_of_fragmented_extension_headers.pop(0)
		while list_of_fragmented_extension_headers:
			l=list_of_fragmented_extension_headers[0]
			fragmentable_part=fragmentable_part/add_extension_header(int(l[0]), size_of_extension_headers, l[1], fuzz)
			list_of_fragmented_extension_headers.pop(0)
		size_of_fragmentable_extension_headers=len(fragmentable_part)
	else:
		first_next_header_value=find_protocol_value_of_layer_4(scapy.layers.inet6.ICMPv6MLQuery())##WHY????????
	return fragmentable_part,size_of_fragmentable_extension_headers,first_next_header_value

def find_protocol_value_of_layer_4(layer4):
	dummy_packet=scapy.layers.inet6.IPv6()/layer4	#dummy packet to get the correct next header value of Layer 4 automatically
	first_next_header_value=dummy_packet.nh 
	return first_next_header_value

#################NO FLOOD - FUZZ################
###IMPLEMENT FLOODING / FUZZING CAPABILITIES####
def create_datagram(mymac,layer2_addr,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,fragment_id,unfragmentable_part,size_of_unfragmentable_part,first_next_header_value,fragmentable_extension_headers,size_of_fragmentable_extension_headers,layer4):
	packets=[]
	if not fragmentable_extension_headers:
		size_of_fragmentable_part=len(layer4)
		fragmentable_part=layer4
	else:
		fragmentable_part=fragmentable_extension_headers/layer4
		size_of_fragmentable_part=size_of_fragmentable_extension_headers+len(layer4)
	#Create the whole datagram now
	IPv6_datagram=unfragmentable_part/fragmentable_part	
	str_IPv6_datagram=str(IPv6_datagram)
	str_fragmentable_part=str_IPv6_datagram[size_of_unfragmentable_part:(size_of_unfragmentable_part+size_of_fragmentable_part+1)]
	#make the fragments
	if number_of_fragments > 0 or list_of_fragment_lengths: 
		if size_of_fragmentable_part/8 < number_of_fragments:
			print "the number of the fragments should not be bigger than the size of the payload"
		elif (size_of_fragmentable_part/number_of_fragments+size_of_unfragmentable_part+8>Ethernet_MTU):
			print "the size of the packet is",size_of_fragmentable_part+size_of_unfragmentable_part,"bytes, which is bigger that the Ethernet MTU. Needs to be fragmented before sending it." 
		else:
				fragmented_parts=frag_datagram(str_fragmentable_part,number_of_fragments,list_of_next_headers,list_of_offsets,list_of_fragment_lengths,list_of_fragment_m_bits,first_next_header_value,fragment_id)
				for frag in fragmented_parts:
					packet=scapy.layers.l2.Ether(src=mymac,dst=layer2_addr)/unfragmentable_part/frag
					packets.append(packet)
	else:
		if not (size_of_fragmentable_part+size_of_unfragmentable_part>Ethernet_MTU):
			packet=scapy.layers.l2.Ether(src=mymac,dst=layer2_addr)/IPv6_datagram
			packets.append(packet)
		else:
			print "the size of the packet is",size_of_fragmentable_part+size_of_unfragmentable_part,"bytes, which is bigger that the Ethernet MTU. Needs to be fragmented before sending it." 
			exit(0)
	return packets

### CREATENFLOOD AND FUZZ CAPABILITIES
def send_packets(mysocket,packets,flood,delay):
	if flood:
		while(True):
			for p in packets:
				mysocket.send(p)
	else:
		for p in packets:
			mysocket.send(p)
			time.sleep(float(delay))

version = '0.9'
# End of create_extension_headers_chain.py
