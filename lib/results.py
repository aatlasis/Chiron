#!/usr/bin/python
# Filename: results.py
version = '0.9'

#make the elements of the imported list unique
#packets which are originated from source, are excluded
#source is used to filter/exclude the packets sent from you.
def unique(imported_list, source):
	opened_tcp_list = []
	sorted_list = []
   	for e in imported_list:
		if not e[0] == source: #exclude packets sent from you
       			if e not in sorted_list:
				if len(e)>3:
					if "MLD" in e[3]:
						found=False
						for p in sorted_list:
							if p[0]==e[0]:
								found=True
								if len(p)==5:
									if len(e)==5:
										if not e[4] in p[4]:
											p[4]=p[4]+e[4]
								elif len(e)==5:
									p.append(e[4])	
						if not found:
           						sorted_list.append(e)
					elif "TCP" in e[1] and e[3]=="SA":
						if e not in opened_tcp_list:
							opened_tcp_list.append(e)
					else:
           					sorted_list.append(e)
				else:
           				sorted_list.append(e)
	return sorted_list,opened_tcp_list

#print the results, one by one, but by making them first unique
def print_results(myresults, source):
	opened_tcp_list = []
	final_results = []
	if myresults:
		final_results,opened_tcp_list=unique(myresults, source)#make them unique
		print_all_results(final_results,opened_tcp_list)		
	return opened_tcp_list,final_results

#just print all the results, one-by-one
def print_all_results(myresults,opened_tcp_list):				
	if myresults:
        	for r in myresults:
        		print r
	if opened_tcp_list:
		print "\n\nOPENED TCP PORTS"
		print "---------------"
		for r in opened_tcp_list:
			print r

#traceroute results
def traceroute_results(results,packets_sent_list):
	routes={}
        for p in packets_sent_list:
            route=[]
            for r in p:
                #print r,p[r]
                for r2 in results:
                    #if int(r2[3],16)==r:
                    if int(r2[3])==r:
                        route.append((p[r][0],r2[0]))
            routes[p.itervalues().next()[1]]=sorted(route)
	return routes

def make_eth_link_global_pairs(myresults):
	my_pairs=[]
	link_local_addresses=[]
	global_addresses=[]
	for r in myresults:
		temp_res=[]
		temp_res.append(r[0])
		temp_res.append(r[1])
		if r[0][0:4]=="fe80":
			link_local_addresses.append(temp_res)
		else:
			global_addresses.append(temp_res)
	for r1 in link_local_addresses:
		temp_res=[]
		found=0
		for r2 in global_addresses:
			if r1[1] == r2[1]: 
				temp_res.append(r1[1])
				temp_res.append(r1[0])
				temp_res.append(r2[0])
				my_pairs.append(temp_res)
				found = 1
				break
		if found==0:  #if there is no corresponding global address but just link-local
			temp_res.append(r1[1])
			temp_res.append(r1[0])
			temp_res.append("")
			my_pairs.append(temp_res)
	for r2 in global_addresses:
		found=0
		for r in my_pairs:
			if r[0] == r2[1]: 
				found=1
				break
		if found==0:  #if there is no corresponding link-local address but just global 
			temp_res=[]
			temp_res.append(r2[1])
			temp_res.append("")
			temp_res.append(r2[0])
			my_pairs.append(temp_res)
	return my_pairs

version = '0.9'
# End of results.py
