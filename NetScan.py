import os
import sys
from modules.python_nmap import nmap
import itertools
import sys
import time
from shutil import which
from math import log2
#from modules.netifaces 
import netifaces as ni

def main():
	if which('nmap') is None:
		Print('''This script needs NMAP to work correctly
				  You can install it via the following command:
				  'pip install nmap' ''')
		exit(0)

	ifname = input("Enter the name of the interface to scan (ex. eth0): ")
	ip = getIP(ifname)
	netmask = getSub(ifname)
	cidr = convertToCidr(netmask)
	network = network_ip(ip, netmask)
	print("IPADDR: "+ip+"\nNETMASK: "+netmask+"\nCIDR: "+str(cidr)+"\nNetwork: "+network)
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
	hosts = str(str(network)+"/"+str(cidr))
	nm = nmap.PortScannerAsync()
	nm.scan(hosts=hosts, arguments='-O --fuzzy', callback=callback)
	spinner = itertools.cycle(['Scanning', 'SCanning', 'ScAnning', 'ScaNning', 'ScanNing', 'ScannIng', 'ScanniNg', 'ScanninG'])
	print("\n")
	while nm.still_scanning():
	    time.sleep(.1)
	    sys.stdout.write(next(spinner))
	    sys.stdout.flush()
	    sys.stdout.write('\b\b\b\b\b\b\b\b')

def callback(host, scan_result):
	alive = str(scan_result['nmap']['scanstats']['uphosts'])
	#print(host+" uphosts: "+alive)
	if alive is "1":
		print("\n\n"+host)
		hostnames = scan_result['scan'][host]['hostnames']
		hostdict = dict()
		for item in hostnames:
			hostdict.update(item)
		if not hostdict['name']:
			print("\n\tHostname: Unknown")
		else:
			print("\n\tHostname: "+str(hostdict['name']))
		#ostype = scan_result['scan'][host]['osmatch']
		#if ostype:
		#	osdict = dict()
		#	for item in ostype:
		#		osdict.update(item)
		#	print("\tOS Type: "+str(osdict['name']))
		#	print("\n")
		#else:
		#	print("\tOS Type: Unknown\n")
		#if scan_result['scan'][host]['tcp']:
		#	print("\tOpen Ports: "+list(plist.keys()))
		#else:
		#	print("\tOpen Ports: None")
main()