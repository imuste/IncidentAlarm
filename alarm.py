#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

alertCounter = 0

def packetcallback(packet):
        global alertCounter

        try:    
                if packet.haslayer(TCP):
                        #NULL Scan
                        if packet[TCP].flags == 0:
                                print(f"ALERT #{alertCounter}: NULL scan is detected from {packet[IP].src} (TCP)!")
                                alertCounter += 1 
                
                        #FIN Scan
                        if packet[TCP].flags == 1:
                                print(f"ALERT #{alertCounter}: FIN scan is detected from {packet[IP].src} (TCP)!")
                                alertCounter += 1 
                        
                        #Xmas Scan
                        if packet[TCP].flags == "FPU":
                                print(f"ALERT #{alertCounter}: Xmas scan is detected from {packet[IP].src} (TCP)!")
                                alertCounter += 1 

                        #Plaintext Username and Password in HTTP
                        if packet[TCP].dport == 80 and packet.haslayer(Raw):
                                packetLoad = packet[Raw].load
                                packetLoadStr = packetLoad.decode()
                                for headerLine in packetLoadStr.splitlines():
                                        if "Authorization: Basic" in headerLine:
                                                val1, val2, userCredEnc = headerLine.partition("Authorization: Basic ")
                                                userCredentials = base64.b64decode(userCredEnc)
                                                userCredentialsStr = userCredentials.decode()
                                                credParts = userCredentialsStr.split(":")
                                                print(f"ALERT #{alertCounter}: Usernames and passwords sent in-the-clear (HTTP) (username:{credParts[0]}, password:{credParts[1]})")
                                                alertCounter += 1 

                        #Plaintext Username and Password in FTP
                        if packet[TCP].dport == 21 and packet.haslayer(Raw):
                                packetLoad = packet[Raw].load
                                packetLoadStr = packetLoad.decode()
                                username = ""
                                password = ""
                                for FTPline in packetLoadStr.splitlines():
                                        if "USER" in FTPline and "PASS" in FTPline:
                                                username = FTPline.split("USER ")[1].strip()
                                                password = FTPline.split("PASS ")[1].strip()
                                                print(f"ALERT #{alertCounter}: Usernames and passwords sent in-the-clear (FTP) (username:{username}, password:{password})")
                                                alertCounter += 1 


                        #Plaintext Username and Password in IMAP
                        if packet[TCP].dport == 143 and packet.haslayer(Raw):
                                packetLoad = packet[Raw].load
                                packetLoadStr = packetLoad.decode()
                                username = ""
                                password = ""
                                for FTPline in packetLoadStr.splitlines():
                                        if "LOGIN" in FTPline:
                                                loginParts = login_line.split()
                                                username = loginParts[2]
                                                password = loginParts[3]
                                                print(f"ALERT #{alertCounter}: Usernames and passwords sent in-the-clear (IMAP) (username:{username}, password:{password})")
                                                alertCounter += 1 
                        
                        #Nikto Scan
                        if packet[TCP].dport == 80 and packet.haslayer(Raw):
                                packetLoad = packet[Raw].load
                                packetLoadStr = packetLoad.decode()
                                if "Nikto" in packetLoadStr:
                                        print(f"ALERT #{alertCounter}: Nikto scan is detected from {packet[IP].src} (HTTP)!")
                                        alertCounter += 1 
                        
                        #SMB Scan
                        if packet[TCP].dport == 139 or packet[TCP].dport == 445:
                                print(f"ALERT #{alertCounter}: SMB scan is detected from {packet[IP].src} (SMB)!")
                                alertCounter += 1 
                        
                        #RDP Scan
                        if packet[TCP].dport == 3389:
                                print(f"ALERT #{alertCounter}: RDP scan is detected from {packet[IP].src} (RDP)!")
                                alertCounter += 1 
                        
                        #VNC Scan
                        if packet[TCP].dport == 5900:
                                print(f"ALERT #{alertCounter}: VNC scan is detected from {packet[IP].src} (TCP)!")
                                alertCounter += 1 


        except Exception as e:
                print(e)
                # pass



# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
        try:
                print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
                sniff(offline=args.pcapfile, prn=packetcallback)    
        except:
                print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
        print("Sniffing on %(interface)s... " % {"interface" : args.interface})
        try:
                sniff(iface=args.interface, prn=packetcallback)
        except:
                print("Sorry, can\'t read network traffic. Are you root?")