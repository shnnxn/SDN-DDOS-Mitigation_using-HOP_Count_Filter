#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet
 
import socket, sys
from struct import *
 
#create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# receive a packet
while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #take first 20 characters for the ip header
    ip_header = packet[0:20]
     
    #now unpack them :)
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
     
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
     
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    if ttl<32:
    	hop_count=32-ttl
	result= "not Droping"
    elif ttl==32:
    	hop_count=0 
	result="Droping"
    elif ttl>32 and ttl<64:
    	hop_count=64-ttl #TTL value 64 is used as default  in Linux based distro
	result= "not Droping" 
    elif ttl==64:
    	hop_count=0 #Same machine therefore no Hop is recorded 
	result="Droping"
    elif ttl>64 and ttl<128:
    	hop_count=128-ttl #TTL value of 128 is used as default by Windows7 based machines
	result= "not Droping"
    elif ttl==128:
	result="Droping"
    	hop_count=0
    elif ttl>128:
    	hop_count=255-ttl
	result= "not Droping"
    elif ttl==255:
	result="Droping"
    	hop_count=0


   

     
    print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) +'Hop Count : '+ str(hop_count)+ ' Result: '+ result + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
     
    tcp_header = packet[iph_length:iph_length+20]
     
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
