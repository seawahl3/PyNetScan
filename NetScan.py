import os
import sys
import nmap
from math import log2
import netifaces as ni

def main():
	#ifname = input("Enter the name of the interface to scan: ")
	#ip = getIP(ifname)
	#netmask = getSub(ifname)
	cidr = str("25") #convertToCidr(netmask)
	network = str("10.200.21.0")#network_ip(ip, netmask)
	#print("IPADDR: "+ip+"\nNETMASK: "+netmask+"\nCIDR: "+str(cidr)+"\nNetwork: "+network)
	activeIPs = scanNet(network, cidr)

def network_ip(ip, netmask):
	network = list()
	b_IP = map(lambda x: bin(x)[2:].zfill(8), map(int, ip.split('.')))
	b_Mask = map(lambda x: bin(x)[2:].zfill(8), map(int, netmask.split('.')))
	for x, y in zip(b_IP, b_Mask):
		network.append(int(x, 2) & int(y, 2))
	return (".".join(map(str, network)))


def getIP(ifname):
	return ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']

def getSub(ifname):
	return ni.ifaddresses(ifname)[ni.AF_INET][0]['netmask']

def convertToCidr(netmask):
	netmask = netmask.split('.')
	cidr = 0
	for i in netmask:
		i = int(i)
		if i != 0:
			i = int(round(log2(i)))
		cidr+=i
	return cidr

def scanNet(network, cidr):
	hosts = str(network+"/"+cidr)
	nm = nmap.PortScannerAsync()
	nm.scan(hosts=hosts, arguments='-O', callback=callback)
	while nm.still_scanning():
		print("\nScanning...")
		nm.wait(30)


def callback(host, scan_result):
	alive = str(scan_result['nmap']['scanstats']['uphosts'])
	print(host+" uphosts: "+alive)
	if alive is "1":
		print(host)
		hostnames = scan_result['scan'][host]['hostnames']
		hostdict = dict()
		for item in hostnames:
			hostdict.update(item)
		print("\n\tHostname: "+str(hostdict['name']))
		ostype = scan_result['scan'][host]['osmatch']
		osdict = dict()
		for item in ostype:
			osdict.update(item)
		print(len(osdict))
		#print("\tOS Type: "+str(osdict['name']))
		print("\n")

	
main()