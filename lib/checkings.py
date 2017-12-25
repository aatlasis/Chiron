#!/usr/bin/python
# Filename: checkings.py
version = '0.9'

def check_fragmentation_parameters(vlist_of_fragment_lengths,vlist_of_offsets,vlist_of_fragment_m_bits,vlist_of_next_headers,vnumber_of_fragments):
	list_of_next_headers=[]
	list_of_offsets=[]
	list_of_fragment_m_bits=[]
	list_of_fragment_lengths=[]
	###List of fragment lengths to be used in the IPv6 Frgment Extension Headers###
	if vlist_of_fragment_lengths:
		if not vlist_of_offsets:
			print "If you want to define arbitrary lengths of fragments, you must also define the list of offsets  for the Fragment Extension Headers using the -lo switch"
			exit(1)
		elif not vlist_of_fragment_m_bits:
			print "If you want to define arbitrary lengths of fragments, you must also define the list of M bits i for the Fragment Extension Headers using the -lm switch"
			exit(1)
		elif not vlist_of_next_headers:
			print "If you want to define arbitrary lengths of fragments, you must also define the Next Header values for the Fragment Extension Headers using the -lnh switch"
			exit(1)
		else:
			list_of_fragment_lengths=vlist_of_fragment_lengths.split(",")
	else:
		list_of_fragment_lengths=vlist_of_fragment_lengths
	###List of Fragment Offset Values to be used in the IPv6 Fragment Extension Headers###
	if vlist_of_offsets:
		list_of_offsets=vlist_of_offsets.split(",")
	###List of M_bit Values to be used in the IPv6 Fragment Extension Headers###
	if vlist_of_fragment_m_bits:
		list_of_fragment_m_bits=vlist_of_fragment_m_bits.split(",")
	###List of Next Header Values to be used in the IPv6 Fragment Extension Headers###
	if vlist_of_next_headers:
		list_of_next_headers=vlist_of_next_headers.split(",")
	#Do some checks
	if vlist_of_fragment_lengths:
		if not int(len(list_of_fragment_lengths))==int(len(list_of_offsets)):
			print "the number of defined fragment offsets using the -lo switch should be equal to the number of the defined fragment lengths, using the -ln switch"
			exit(1)
		elif not int(len(list_of_fragment_lengths))==int(len(list_of_next_headers)):
			print "the number of defined next header values using the -lnh  switch should be equal to the number of the defined fragment lengths, using the -ln switch"
			exit(1)
		elif not int(len(list_of_fragment_lengths))==int(len(list_of_fragment_m_bits)):
			print "the number of defined M (More Fragment to Follow) bits using the -lm switch should be equal to the number of the defined fragment lengths, using the -ln switch"
			exit(1)
	elif vlist_of_fragment_m_bits and (int(vnumber_of_fragments) > int(len(list_of_fragment_m_bits))):
			print "If you want to define your own list of M (More fragments to follow) bits to be used at Fragment Extension Headers in case of fragmentation, the number of next header values should be at least the same as the number of fragments"
			print "Number of fragments = ", vnumber_of_fragments
			print "Number of next header values = ", len(list_of_fragment_m_bits) 
			print "Exiting..."
			exit(1) 
	elif vlist_of_offsets and (int(vnumber_of_fragments) > int(len(list_of_offsets))):
			print "If you want to define your own list of fragment offset values to be used at Fragment Extension Headers in case of fragmentation, the number of fragment offset values should be at least the same as the number of fragments"
			print "Number of fragments = ", vnumber_of_fragments
			print "Number of offsets = ", len(list_of_offsets) 
			print "Exiting..."
			exit(1) 
	elif vlist_of_next_headers and (int(vnumber_of_fragments) > int(len(list_of_next_headers))):
			print "If you want to define your own list of next headers values to be used at Fragment Extension Headers in case of fragmentation, the number of next header values should be at least the same as the number of fragments"
			print "Number of fragments = ", vnumber_of_fragments
			print "Number of next header values = ", len(list_of_next_headers) 
			print "Exiting..."
			exit(1) 
	return list_of_fragment_lengths,list_of_offsets,list_of_fragment_m_bits,list_of_next_headers

version = '0.9'
# End of  checkings.py
