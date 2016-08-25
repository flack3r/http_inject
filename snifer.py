#!/usr/bin/python
import time
from scapy.all import *
import copy

stars = lambda n: "*" * n
stop_flag = False
def Filter_handle(packet):
	global stop_flag
	print "========original========"
	packet.show()

	Eth_h = packet[Ether]
	IP_h = packet[IP]
	TCP_h = packet[TCP]
	
	#====stage1====
	### send "block" to server ###
	packet2 = copy.deepcopy(packet)
	Eth_h1 = packet2[Ether]
	IP_h1 = packet2[IP]
	TCP_h1 = packet2[TCP]

	#change tcp to fin packet
	TCP_h1.flags = 'FA'
	TCP_h1.load = "blocked\r\n"
	TCP_h1.seq += len(TCP_h.load)
	
	##check sum calc
	PacketToServer = packet2
	del PacketToServer[IP].chksum
	del PacketToServer[IP].len
	del PacketToServer[TCP].chksum
	
	PacketToServer.show2()
	sendp(PacketToServer)

	#====stage2====
	### send backward fin ###
	# packet3 = copy.deepcopy(packet)
	# Eth_h2 = packet3[Ether]
	# IP_h2 = packet3[IP]
	# TCP_h2 = packet3[TCP]

	# Eth_h2.dst = Eth_h.src;
	# Eth_h2.src = Eth_h.dst;
	# IP_h2.dst = IP_h.src;
	# IP_h2.src = IP_h.dst;

	# TCP_h2.flags = 'FA'
	# TCP_h2.seq = TCP_h.ack
	# TCP_h2.ack = TCP_h.seq
	# TCP_h2.sport = TCP_h.dport
	# TCP_h2.dport = TCP_h.sport
	# del TCP_h2.load
	# TCP_h2.load = "blocked host\r\n"

	##check sum calc
	# PacketToServer = packet3
	# del PacketToServer[IP].chksum
	# del PacketToServer[IP].len
	# del PacketToServer[TCP].chksum
	# PacketToServer.show2()
	# sendp(PacketToServer)

	#====stage3====
	### send backward to fin 
	packet4 = copy.deepcopy(packet)

	Eth_h3 = packet4[Ether]
	IP_h3 = packet4[IP]
	TCP_h3 = packet4[TCP]

	Eth_h3.dst = Eth_h.src;
	Eth_h3.src = Eth_h.dst;
	IP_h3.dst = IP_h.src;
	IP_h3.src = IP_h.dst;

	TCP_h3.seq = TCP_h.ack
	TCP_h3.ack = TCP_h.seq + len(TCP_h.load)
	TCP_h3.sport = TCP_h.dport
	TCP_h3.dport = TCP_h.sport
	del TCP_h3.load
	TCP_h3.load = "HTTP/1.1 302 Found \r\nLocation: https://en.wikipedia.org/wiki/HTTP_302 \r\n\r\n\x00"

	PacketToServer = packet4
	#check sum calc
	del PacketToServer[IP].chksum
	del PacketToServer[IP].len
	del PacketToServer[TCP].chksum
	PacketToServer.show2()
	sendp(PacketToServer)
	stop_flag = True;
	del packet
	return


def stopfilter(x):
	global stop_flag
	if stop_flag == True:
		return True
	else:
		return False
sniff(iface='eth0', prn=Filter_handle, lfilter=lambda p: "GET" in str(p), filter="tcp port 80", store=0)
