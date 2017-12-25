#!/usr/bin/python
import sys
import os
sys.path.append('../lib')
import sniffer_process
import scapy

def main():
	if len(sys.argv)==4:
		scapy.config.conf.verb=0
		scapy.layers.inet6.conf.verb=0
		j=sys.argv[1]
		prefix=sys.argv[2]
		filename=sys.argv[3]
		the_prefix=prefix+":*:*:*"
		f=open(filename,'w')
		for i in range(int(j)):
			x=scapy.layers.inet6.RandIP6(the_prefix)+"::"
			f.write(x+"\n")
		f.close()
	else:
		print "Please provide a) the number of prefixes you want to generate, b) the first two octects of the prefixes (e.g. 2001) and c) the filename where you want store the prefixes"

if __name__ == '__main__':
	main()
