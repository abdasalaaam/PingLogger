from os import times
import struct
import socket
import threading
import random
import time

systemIP = '54.158.136.143'
pcIP = '10.4.3.27'
destPort = 33434
portsBeingUsed = [] #port number has to be changed for each sent packet
startTime = round(time.time(),3)

def IPaddresses():
    targets = open('targets.txt')
    IPmatch = []
    for url in targets:
        site = url.rstrip()
        IP = socket.gethostbyname(site)
        IPmatch.append(IP)
    return IPmatch

def receive():
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    #recv_sock.bind(“”,0)
    while True:
        match = "n/a"
        IPchanged = False
        
        icmp_packet = recv_sock.recv(1500)
        recTime = int(round(time.time()-startTime,3)*1000)
        rtt = recTime%30000-icmp_packet[32:34]
        hops = 255 - icmp_packet[36]
        responseSourceIP = socket.inet_ntoa(icmp_packet[12:16]) #the sourceIP from the sender
        customHeaderSIP = socket.inet_ntoa(icmp_packet[40:44])

        hostname = socket.gethostbyaddr(responseSourceIP)
        responseDestIP = socket.inet_ntoa(icmp_packet[16:20])   #the destinationIP from the sender
        customHeaderDIP = socket.inet_ntoa(icmp_packet[44:48])
        if responseSourceIP == customHeaderDIP:
            match = responseSourceIP
        else:
            IPchanged = True
        print("Target: " + hostname + ":" + responseSourceIP + "; Hops: " + hops + "; RTT: " + rtt + " ms; Matched on: " + match)
        if IPchanged == True:
            print("Destination IP changed in route: " + responseSourceIP)
        

def genPort():
    notSamePort = True
    port = 0
    while notSamePort:
        port = random.randrange(50000, 65000)
        if not port in portsBeingUsed:
            notSamePort = False
            portsBeingUsed.append(port)
    return port

def send():
    #raw socket
    msg = "measurement for class project. questions to student ass112@case.edu or professor mxr136@case.edu"
    sockSend = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    payload = bytes(msg + "a" * (1472 - len(msg)),'ascii')
    for dest_ip in IPaddresses:
        time = int(round(time.time()-startTime,3)*1000) #time relative to start of program 
        #Ip header info
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0	# kernel will fill the correct total length
        ip_idTime = time%30000	#Sets the id to the TIME!
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0	# kernel will fill the correct checksum
        ip_saddr = socket.inet_aton ( pcIP )	#Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton ( dest_ip )
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        #Udp header info
        sourcePort = genPort
        checksum = 0
        length = len(payload)+8
        #creation of headers
                                #               1 byte      1 byte  2 byte      2 bytes     2 bytes     1 byte  1 byte     2 byte     4 letter string
        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_idTime, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
                                #         2 byte      2 byte    2 byte  2 byte
        udp_header = struct.pack('!HHHH', sourcePort, destPort, length, checksum)
        #info to place in each packet
        probe_packet = ip_header + udp_header + payload
        sockSend.sendto(probe_packet, (dest_ip, destPort))
    sockSend.close()


def distMeasure():
    threading.Thread(target=receive()).start()
    threading.Thread(target=send()).start()

distMeasure()