import os
import sys
from modules.python_nmap import nmap
import itertools
import sys
import time
from shutil import which
from math import log2
import netifaces as ni

# When run, the script asks for specific interface to scan.
# The list of interfaces can be found by typing 'ifconfig' into the console
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

	
# Generates a Networks IP address using a given IP address
# and Subnetmask from a machine on the network
def network_ip(ip, netmask):
	network = list()
	b_IP = map(lambda x: bin(x)[2:].zfill(8), map(int, ip.split('.')))
	b_Mask = map(lambda x: bin(x)[2:].zfill(8), map(int, netmask.split('.')))
	for x, y in zip(b_IP, b_Mask):
		network.append(int(x, 2) & int(y, 2))
	return (".".join(map(str, network)))

# Retrieves the IP address linked to the interface given by the user
def getIP(ifname):
	return ni.ifaddresses(ifname)[ni.AF_INET][0]['addr']

# Retrieves the Subnetmask linked to the interface given by the user
def getSub(ifname):
	return ni.ifaddresses(ifname)[ni.AF_INET][0]['netmask']


# Using the given Subnetmask, generates Classless inter-domain routing number 
# Examples
#	255.255.255.255 = ***.***.***.***/32
#	255.255.255.254 = ***.***.***.***/31
#	255.255.255.252 = ***.***.***.***/30
#	255.255.255.248 = ***.***.***.***/29
#	255.255.255.240 = ***.***.***.***/28
def convertToCidr(netmask):
	netmask = netmask.split('.')
	cidr = 0
	for i in netmask:
		i = int(i)
		if i != 0:
			i = int(round(log2(i)))
		cidr+=i
	return cidr

# Uses the Network IP and Cidr number to scan a network using nmap
def scanNet(network, cidr):
	hosts = str(str(network)+"/"+str(cidr))
	nm = nmap.PortScannerAsync()
	nm.scan(hosts=hosts, arguments='-O --fuzzy', callback=callback)
	spinner = itertools.cycle(['Scanning', 'SCanning', 'ScAnning', 'ScaNning', 'ScanNing', 'ScannIng', 'ScanniNg', 'ScanninG'])
	print("\n")
	while nm.still_scanning(): # Creates a Loading animation while waiting
	    time.sleep(.1)
	    sys.stdout.write(next(spinner))
	    sys.stdout.flush()
	    sys.stdout.write('\b\b\b\b\b\b\b\b')


# Returns the Host names of active machines on a network
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
main()
