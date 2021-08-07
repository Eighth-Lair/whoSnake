
		##############################
		##                          ##
		##       whoSnake.py        ##
		##  Written by MadMartigan  ##
		##                          ##
		##############################

import os
import sys
import argparse
import re
#from scapy.utils import RawPcapReader
from scapy.all import *
#import ipwhois
from ipwhois import IPWhois

def count_pcap(file_name):
	'''Counts and prints total number of packets in the pcap'''
	print(f'Opening "{file_name}"...')

	count = 0
	for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
		count += 1

	print(f'"{file_name}" contains {count} packets!')

def get_ip(file_name):
	'''Read the pcap, extract all IP addresses and then remove unwanted IPs'''
	packet_list = rdpcap(file_name)
	tmplist_src = []
	tmplist_dst = []

	for pkt in packet_list:
		if IP in pkt:
			ipsrc = pkt['IP'].src
			ipdst = pkt['IP'].dst  
			
			if ipsrc not in tmplist_src:
				tmplist_src.append(ipsrc)
			
			if ipdst not in tmplist_dst:
				tmplist_dst.append(ipdst)

	for ip in tmplist_dst:
		tmplist_src.append(ip) 

	# Use regex to remove all private and multicast IP addresses
	ip_list = []	
	for ip in tmplist_src:
		if re.match("(^0\.0)|(^127\.)|(^10\.)|(^172\.)|(^192\.)|(^255\.255)|(^239\.)|(^224\.)", ip):
			print(f"Removed IP: {ip}")
			pass

		else:
			ip_list.append(ip)

	return ip_list

def get_whois(ListOfIPs):
	'''Run whois on each IP and print formatted data''' 
	
	for ip in ListOfIPs:
		whois_data = IPWhois(ip, allow_permutations=True)
		resolved = whois_data.lookup_whois()
		name = resolved["nets"][0]["name"]
		description = resolved["nets"][0]["description"]
		
		print(f"{ip}: {name}, {description}")


if __name__ == '__main__':
	'''Set required arguments and error messages'''
	parser = argparse.ArgumentParser(description='PCAP Reader')
	parser.add_argument('--pcap', metavar='<pcap file name>',
						help='pcap file to parse', required=True)
	args = parser.parse_args()

	file_name = args.pcap
	if not os.path.isfile(file_name):
		print(f'"{file_name}" does not exist.', file=sys.stderr)
		sys.exit(-1)

	
	# Call functions and do work

	count_pcap(file_name)
	
	# Build a list of IPs from the provided capture file
	ListOfIPs = get_ip(file_name)
	
	# Run whois search against each from the pcap and dump formated data
	get_whois(ListOfIPs)

	##print statement for trouble shooting . 
#	print(ListOfIPs)

	print("Finished!")
	sys.exit(0)