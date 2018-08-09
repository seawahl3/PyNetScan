import os
import sys
import nmap as nm
from math import log2
import netifaces as ni

def main():
	ifname = input("Enter the name of the interface to scan: ")
	ip = getIP(ifname)
	netmask = getSub(ifname)
	cidr = convertToCidr(netmask)
	network = network_ip(ip, netmask)
	print("IPADDR: "+ip+"\nNETMASK: "+netmask+"\nCIDR: "+str(cidr)+"\nNetwork: "+network)
	#activeIPs = scanNet(ip, cidr)

def network_ip(ip, netmask):
	network = list()
	b_IP = map(lambda x: bin(x)[2:].zfill(8), map(int, ip.split('.')))
	b_Mask = map(lambda x: bin(x)[2:].zfill(8), map(int, netmask.split('.')))
	for x, y in zip(b_IP, b_Mask):
		network.append(int(x, 2) & int(y, 2))
	return (".".join(map(str, network)))


def getIP(ifname):
	#ni.ifaddresses(ifname)
	ip = ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']
	return ip

def getSub(ifname):
	#ni.ifaddresses(ifname)
	netmask = ni.ifaddresses(ifname)[ni.AF_INET][0]['netmask']
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

#def scanNet(ip, cidr):
#	hosts = str(ip+"/"+cidr)
#	nm=nm.PortScanner()
#	nm.scan(hosts=hosts, arguuments= )
	
main()

