#!/usr/bin/python
# Filename: sniffer_process.py
#import multiprocessing
from scapy.all import *
version = '0.9'

class mySniffer():
    def __init__ (self,interface,scan_type,q,sniffer_timeout,source_ip,dns_server):
        self.interface = interface
        self.scan_type=scan_type
	self.q=q
	self.sniffer_timeout=sniffer_timeout
        self.source_ip=source_ip
        self.dns_server=dns_server
	print "Starting sniffing..."
        if self.sniffer_timeout:
    	    sniff(iface=self.interface, prn=self.handler, store=0, timeout=float(self.sniffer_timeout))
        else:
    	    sniff(iface=self.interface, prn=self.handler, store=0, count=0, timeout=None)
    def handler(self,packets):
	res=[]
        if packets.haslayer(IPv6):
            #print "Scan type=", self.scan_type
            #print self.scan_type,packets.summary()
            if (self.scan_type==1 or self.scan_type==5 or (packets[IPv6].dst==self.source_ip and not packets[IPv6].src==self.dns_server)):
            #if (self.scan_type==1 or self.scan_type==5 and not packets[IPv6].src==self.dns_server):
                if packets.haslayer(ICMPv6DestUnreach):
			if not self.scan_type==6: #NOT NEEDED
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1 or self.scan_type==5:
					res.append(packets.sprintf("%src%"))
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6DestUnreach.type%"))
				res.append(packets.sprintf("%ICMPv6DestUnreach.code%"))
				if packets.payload.payload.payload.nh==17:#if UDP
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6DestUnreach.type% %ICMPv6DestUnreach.code% Target:"),packets.payload.payload.payload.sprintf("%dst%"),packets.payload.payload.payload.payload.sprintf("UDP port %dport% CLOSED")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("UDP port %dport% CLOSED"))
				elif packets.payload.payload.payload.nh==6:#if TCP
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6DestUnreach.type% %ICMPv6DestUnreach.code% Target:"),packets.payload.payload.payload.sprintf("%dst%"),packets.payload.payload.payload.payload.sprintf("TCP port %dport% CLOSED")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("TCP port %dport% CLOSED"))
				elif packets.payload.payload.payload.nh==58:#if ICMPv6
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6DestUnreach.type% %ICMPv6DestUnreach.code% Enclosed Protocol:"),packets.payload.payload.sprintf("%nh%"),packets.payload.payload.payload.sprintf("%type% %code%")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("Type: %type%"))
					res.append(packets.payload.payload.payload.payload.sprintf("Code: %code%"))
				else:
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6DestUnreach.type% %ICMPv6DestUnreach.code% Enclosed Protocol:"),packets.payload.payload.sprintf("%nh%")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.sprintf("Enclosed protocol: %nh%"))
                elif packets.haslayer(ICMPv6ParamProblem):
			if not self.scan_type==6:
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6ParamProblem.type% %ICMPv6ParamProblem.code%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1 or self.scan_type==5:
					res.append(packets.sprintf("%src%"))
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6ParamProblem.type%"))
				res.append(packets.sprintf("%ICMPv6ParamProblem.code%"))
				res.append(packets.sprintf("%ICMPv6ParamProblem.ptr%"))
                elif packets.haslayer(ICMPv6TimeExceeded):
			if self.scan_type==6: ###THIS IS NEVER TRUE
				returned_packet=packets.getlayer(ICMPv6TimeExceeded)
				if returned_packet.haslayer(ICMPv6EchoRequest):
					embedded_packet=returned_packet.getlayer(ICMPv6EchoRequest)
					res.append(packets.payload.sprintf("%IPv6.src%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.type%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.code%"))
					res.append(int(returned_packet.sprintf("%ICMPv6EchoRequest.id%"),16))
					print packets.payload.src,packets.sprintf("%ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code%")
				elif returned_packet.payload.haslayer(TCPerror):
					embedded_packet=returned_packet.getlayer(TCPerror)
					res.append(packets.payload.sprintf("%IPv6.src%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.type%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.code%"))
					res.append(embedded_packet.sport)
					packets.payload.src,packets.sprintf("%ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code%")
					print packets.payload.src,packets.sprintf("%ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code%")
				elif returned_packet.payload.haslayer(UDPerror):
					embedded_packet=returned_packet.getlayer(UDPerror)
					res.append(packets.payload.sprintf("%IPv6.src%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.type%"))
					res.append(returned_packet.sprintf("%ICMPv6TimeExceeded.code%"))
					res.append(embedded_packet.sport)
					print packets.payload.src,packets.sprintf("%ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code%")
				else:
					print returned_packet.summary()
			else:
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1 or self.scan_type==5:
					res.append(packets.sprintf("%src%"))
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6TimeExceeded.type%"))
				res.append(packets.sprintf("%ICMPv6TimeExceeded.code%"))
				if packets.payload.payload.payload.nh==17:#if UDP
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code% Target:"),packets.payload.payload.payload.sprintf("%dst%"),packets.payload.payload.payload.payload.sprintf("UDP port %dport% CLOSED")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("UDP port %dport% CLOSED"))
				elif packets.payload.payload.payload.nh==6:#if TCP
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code% Target:"),packets.payload.payload.payload.sprintf("%dst%"),packets.payload.payload.payload.payload.sprintf("TCP port %dport% CLOSED")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("TCP port %dport% CLOSED"))
				elif packets.payload.payload.payload.nh==58:#if ICMPv6
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code% Enclosed Protocol:"),packets.payload.payload.sprintf("%nh%"),packets.payload.payload.payload.sprintf("%type% %code%")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.payload.sprintf("Type: %type%"))
					res.append(packets.payload.payload.payload.payload.sprintf("Code: %code%"))
				else:
                			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% ICMPv6 %ICMPv6TimeExceeded.type% %ICMPv6TimeExceeded.code% Enclosed Protocol:"),packets.payload.payload.sprintf("%nh%")
					res.append(packets.payload.payload.payload.sprintf("Target: %dst%"))
					res.append(packets.payload.payload.payload.sprintf("Enclosed protocol: %nh%"))
                elif packets.haslayer(ICMPv6PacketTooBig):
			if not self.scan_type==6:  #NOT NEEDED
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6PacketTooBig.type% %ICMPv6PacketTooBig.code% %ICMPv6PacketTooBig.mtu%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1 or self.scan_type==5:
					res.append(packets.sprintf("%src%"))
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6PacketTooBig.type%"))
				res.append(packets.sprintf("%ICMPv6PacketTooBig.code%"))
				res.append(packets.sprintf("%ICMPv6PacketTooBig.mtu%"))
	        elif packets.haslayer(IPv6ExtHdrRouting):
			print packets.sprintf("%src% %IPv6.src%  -> %IPv6.dst% %IPv6ExtHdrRouting.type% %IPv6ExtHdrRouting.addresses% %IPv6ExtHdrRouting.segleft%")
			res.append(packets.sprintf("%IPv6.src%"))
			if self.scan_type==1:
				res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf("%IPv6.dst%"))
			res.append(packets.sprintf("%IPv6ExtHdrRouting.nh%"))
			res.append(packets.sprintf("%IPv6ExtHdrRouting.type%"))
			res.append(packets.sprintf("%IPv6ExtHdrRouting.segleft%"))
			res.append(packets.sprintf("%IPv6ExtHdrRouting.addresses%"))
			#res.append(packets.sprintf("%src%"))
	        elif packets.haslayer(IPv6ExtHdrFragment):
				returned_packet=packets.getlayer(IPv6ExtHdrFragment)
				print returned_packet.summary()
				res.append(returned_packet.summary())
                elif packets.haslayer(ICMPv6EchoReply) and not self.scan_type==3 and not self.scan_type==4 and not self.scan_type==7 and not self.scan_type==6:
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6EchoReply.type%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1 or self.scan_type==5:
					res.append(packets.sprintf("%src%"))
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6EchoReply.type%"))
				res.append(packets.sprintf("%ICMPv6EchoReply.id%"))
				res.append(packets.sprintf("%ICMPv6EchoReply.data%"))
				#res.append(packets.sprintf("%ICMPv6EchoReply.seq%"))
                elif packets.haslayer(ICMPv6EchoRequest) and self.scan_type==1:
                	print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6EchoRequest.type%")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6EchoRequest.type%"))
			res.append(packets.sprintf("%ICMPv6EchoRequest.id%"))
			res.append(packets.sprintf("%ICMPv6EchoRequest.data%"))
			#res.append(packets.sprintf("%ICMPv6EchoRequest.seq%"))
                elif packets.haslayer(IPv6ExtHdrHopByHop) and (self.scan_type==1 or self.scan_type==8):
			#print "Hop-by-Hop Header"
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
        		if packets.payload.haslayer(ICMPv6MLReport):
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLReport.type% %ICMPv6MLReport.mladdr%")
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6MLReport.type%"))
				multicast_address=packets.payload.getlayer(ICMPv6MLReport).mladdr
				if multicast_address=="ff02::1:3":
					res.append("Windows")
				elif multicast_address=="ff02::c":
					res.append("/Client/")
				elif "ff02::2:ff" in multicast_address:
					res.append("FreeBSD")
				elif "ff02::1:2" in multicast_address or "ff05::1:3" in multicast_address:
					res.append("/DHCPv6 Server-Relay/")
				elif ":7fff" in multicast_address:
					res.append("SAPv0")
				elif ":7ffe" in multicast_address:
					res.append("SAPv1")
				else:
					res.append(packets.sprintf("/%ICMPv6MLReport.mladdr%/"))
        		elif packets.payload.haslayer(ICMPv6MLDone):
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLDone.type% %ICMPv6MLDone.mladdr%")
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6MLDone.type%"))
				multicast_address=packets.payload.getlayer(ICMPv6MLDone).mladdr
				if multicast_address=="ff02::1:3":
					res.append("/Windows/")
				elif multicast_address=="ff02::c":
					res.append("/Client/")
				elif "ff02::2:ff" in multicast_address:
					res.append("/FreeBSD/")
				elif "ff02::1:2" in multicast_address or "ff05::1:3" in multicast_address:
					res.append("/DHCPv6 Server-Relay/")
				elif "::2:7fff" in multicast_address:
					res.append("/SAPv0/")
				elif "::2:7ffe" in multicast_address:
					res.append("/SAPv1/")
				else:
					res.append(packets.sprintf("/%ICMPv6MLReport.mladdr%/"))
        		elif packets.payload.haslayer(ICMPv6MLQuery):
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLQuery.type%")
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6MLQuery.type%"))
				res.append("MLD capable router")
        		elif packets.payload.haslayer(ICMPv6MLReport2):
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLReport2.type%")
				res.append(packets.sprintf(" ICMPv6 "))
				res.append(packets.sprintf("%ICMPv6MLReport2.type%"))
			else:
                		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLReport2.type%")
				#print packets.payload.show()
                elif packets.haslayer(TCP) and (self.scan_type==3 or self.scan_type==1):
                		print packets.sprintf("%src% %IPv6.src% %dst% -> %IPv6.dst% TCP %TCP.sport% %TCP.dport% %TCP.flags%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1:
					res.append(packets.sprintf("%src%"))
					res.append(packets.sprintf(" TCP "))
					res.append(packets.sprintf("sport=%TCP.sport%"))
					res.append(packets.sprintf("dport=%TCP.dport%"))
					res.append(packets.sprintf("TCPflags=%TCP.flags%"))
				else:
					res.append(packets.sprintf(" TCP "))
					res.append(packets.sprintf("%TCP.sport%"))
					res.append(packets.sprintf("%TCP.flags%"))
                elif packets.haslayer(UDP) and (self.scan_type==4 or self.scan_type==1 or self.scan_type==8): #8 is for DHCPv6 operation
                        layer4_header=packets.getlayer(UDP)
			if (layer4_header.sport==546 and layer4_header.dport==547):
				print "DHCPv6 packet"
				if layer4_header.haslayer(DHCP6_Solicit):
                			print "DHCPv6 Solicit message. Transaction ID =",layer4_header.sprintf("%DHCP6_Solicit.trid%")
					if layer4_header.haslayer(DHCP6OptClientId):
						print "Client DUID =",layer4_header.sprintf("%DHCP6OptClientId.duid%") 
						ClientID=layer4_header.getlayer(DHCP6OptClientId)
						print "Client Identifier =",ClientID.show()
			else:
               			print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% UDP %UDP.sport% %UDP.dport%")
				res.append(packets.sprintf("%IPv6.src%"))
				if self.scan_type==1:
					res.append(packets.sprintf("%src%"))
					res.append(packets.sprintf(" UDP "))
					res.append(packets.sprintf("sport=%UDP.sport%"))
					res.append(packets.sprintf("dport=%UDP.dport%"))
				else:	
					res.append(packets.sprintf(" UDP "))
					res.append(packets.sprintf("%UDP.sport%"))
            if packets.haslayer(ICMPv6ND_NA) and self.scan_type==1:
                	print packets.sprintf("%src% %IPv6.src%  -> %IPv6.dst% %ICMPv6ND_NA.type% %ICMPv6ND_NA.tgt% ")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6ND_NA.type%"))
			#res.append(packets.sprintf("%ICMPv6ND_NA.code%"))
			res.append(packets.sprintf("%ICMPv6ND_NA.R%"))
			res.append(packets.sprintf("%ICMPv6ND_NA.S%"))
			res.append(packets.sprintf("%ICMPv6ND_NA.O%"))
			res.append(packets.sprintf("%ICMPv6ND_NA.tgt%"))
            elif packets.haslayer(ICMPv6ND_NS) and self.scan_type==1:
                	print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6ND_NS.type% %ICMPv6ND_NS.tgt% ")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6ND_NS.type%"))
			#res.append(packets.sprintf("%ICMPv6ND_NS.code%"))
			res.append(packets.sprintf("%ICMPv6ND_NS.tgt%"))
            elif packets.haslayer(ICMPv6ND_RA) and self.scan_type==1:
                	print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6ND_RA.type%")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6ND_RA.type%"))
			#res.append(packets.sprintf("%ICMPv6ND_RA.code%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.chlim%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.M%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.O%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.H%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.prf%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.P%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.routerlifetime%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.reachabletime%"))
			res.append(packets.sprintf("%ICMPv6ND_RA.retranstimer%"))
			if packets.haslayer(ICMPv6NDOptPrefixInfo):
				res.append(packets.sprintf("%ICMPv6NDOptPrefixInfo.prefix%"))
				res.append(packets.sprintf("%ICMPv6NDOptPrefixInfo.prefixlen%"))
				res.append(packets.sprintf("%ICMPv6NDOptPrefixInfo.L%"))
				res.append(packets.sprintf("%ICMPv6NDOptPrefixInfo.A%"))
				res.append(packets.sprintf("%ICMPv6NDOptPrefixInfo.R%"))
				res.append(int(packets.sprintf("%ICMPv6NDOptPrefixInfo.validlifetime%"),16))
				res.append(int(packets.sprintf("%ICMPv6NDOptPrefixInfo.preferredlifetime%"),16))
            elif packets.haslayer(ICMPv6ND_RS) and self.scan_type==1:
                	print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6ND_RS.type%")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6ND_RS.type%"))
			res.append(packets.sprintf("%ICMPv6ND_RS.code%"))
            elif packets.haslayer(ICMPv6MLReport) and self.scan_type==1:
               		print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %ICMPv6MLReport.type% %ICMPv6MLReport.mladdr%")
			res.append(packets.sprintf("%IPv6.src%"))
			res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf(" ICMPv6 "))
			res.append(packets.sprintf("%ICMPv6MLReport.type%"))
			res.append(packets.sprintf("%ICMPv6MLReport.code%"))
			res.append(packets.sprintf("%ICMPv6MLReport.mrd%"))
			res.append(packets.sprintf("%ICMPv6MLReport.mladdr%"))
            elif not self.scan_type==2 and not self.scan_type==5 and not self.scan_type==3 and not self.scan_type==6 and not self.scan_type==7:
                	print packets.sprintf("%src% %IPv6.src% -> %IPv6.dst% %IPv6.nh%")
			#res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf("%IPv6.src%"))
			if self.scan_type==1:
				res.append(packets.sprintf("%src%"))
			res.append(packets.sprintf("%IPv6.nh%"))
	if res:
	    self.q.put(res)
version = '0.9'
# End of sniffer_process.py
