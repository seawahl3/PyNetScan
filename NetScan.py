import os
import sys
import nmap
from math import log2
import netifaces as ni

def main():
	ifname = input("Enter the name of the interface to scan: ")
	ip = getIP(ifname)
	netmask = getSub(ifname)
	cidr = convertToCidr(netmask)
	print("IPADDR: "+ip+"\nNETMASK: "+netmask+"\nCIDR: "+str(cidr))


def getIP(ifname):
	ni.ifaddresses(ifname)
	ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
	print(ip)
	return ip

def getSub(ifname):
	ni.ifaddresses(ifname)
	netmask = ni.ifaddresses(ifname)[ni.AF_INET][0]['netmask']
	print(netmask)
	return netmask

def convertToCidr(netmask):
	netmask = netmask.split('.')
	cidr = 0
	for i in netmask:
		i = int(i)
		if i != 0:
			i = int(round(log2(i)))
		cidr+=i
	return cidr
	

main()

