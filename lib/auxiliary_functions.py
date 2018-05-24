#!/usr/bin/python
# Filename: auxiliary_functions.py
import scapy.all
version = '0.9'

def get_my_ip(interface):
	myip=""
	try:
		mymac = scapy.layers.l2.get_if_hwaddr(interface) #my MAC address
		for ifaces in scapy.arch.linux.in6_getifaddr(): 	 #in6_getifaddr()  #return a list of IPs - ifaces, etc
			if ifaces[2]==interface:
				if not myip:
					myip=ifaces[0]
				elif myip[0:6] == "fe80::":
					myip=ifaces[0]	
		return myip
	except:
		print "The interface",interface,"does not exist. Please, try again."
		exit(0)

def get_my_link_local_ip(interface):
	myip=""
	try:
		mymac = scapy.layers.l2.get_if_hwaddr(interface) #my MAC address
		for ifaces in scapy.arch.linux.in6_getifaddr(): 	 #in6_getifaddr()  #return a list of IPs - ifaces, etc
			if ifaces[2]==interface:
				if ifaces[0][0:6] == "fe80::":
					myip=ifaces[0]	
					break
		return myip
	except:
		print "The interface",interface,"does not exist. Please, try again."
		exit(0)

###GET THE GATEWAY MAC ADDRES###
def get_gw_mac(vgateway,vinterface,ip_list,source_ip): 
	gw_mac=""
	if vgateway:
		targets=ip_list
		gw_mac = configure_routing(source_ip, vgateway, vinterface)
		print "The MAC address of your gateway is", gw_mac
	else:
		scapy.route6.conf.route6.resync()
		p=scapy.route6.conf.route6.route("::/0",dev=vinterface)
		if not p[0] == vinterface:
			print "System's default gateway for interface",vinterface,"not found, or there are two default gateways"
			print "If you need to use a gateway, you must define it on your own"
		elif not p[1][0:6] == "fe80::":
			gw_mac=find_single_mac(p[1], p[2], p[0])
			print "Using system's default gateway",p[1],"with MAC address",gw_mac,"if needed"
	return gw_mac

def find_single_mac(source, destination, interface):
	if source==destination:
		return scapy.layers.l2.get_if_hwaddr(interface)
	else:
		p=scapy.layers.inet6.neighsol(destination,source,interface,0)
		if p:
			return p.lladdr
		else:
			#for ifaces in scapy.layers.inet6.in6_getifaddr(): 	 #in6_getifaddr()  #return a list of IPs - ifaces, etc
			for ifaces in scapy.route6.in6_getifaddr(): 	 #in6_getifaddr()  #return a list of IPs - ifaces, etc
				if ifaces[0]==destination:
					return scapy.layers.l2.get_if_hwaddr(interface)

def configure_routing(source, gateway, interface):
	p=scapy.layers.inet6.neighsol(gateway,source,interface,0)
	scapy.route6.conf.route6.add(dst="::/0", gw=gateway, dev=interface)
	try:
		return p.lladdr
	except:
		print "Gateway ",gateway," was not found"
		exit(0)

version = '0.9'
# End of  auxiliary_functions.py
