#!/usr/bin/env python

import sys, os, signal
import time
import datetime
import urllib2
from scapy.all import *
import logging
from scapy.layers.inet import IP
from multiprocessing import Process


# process unique sniffed Beacons and ProbeResponses. 
clientprobe=[]
mac=""
def sniffAP(p):
	global clientprobe
	if p.haslayer(Dot11ProbeReq):
		#print p.addr1 +"- "+ p.addr2+"-"+ p.info
		#print str(p.haslayer) + "--"+ str(p .type) + "--" + str(p.subtype)

		if len(p.info) > 0:
			testcase = p.addr2 + "---" + p.info
			if testcase not in clientprobe :
				clientprobe.append(testcase)
				a=str(datetime.datetime.today())
				macvendor(p.addr2)
				global mac
				print "New probe found: |" +a+"|"+ p.addr2 +"|"+mac + "|" + p.info
				#print "New probe found: |" +a+"|"+ p.addr2 + "|" + p.info
				#print clientprobe
def macvendor(macv):
        try :
                global mac
		TimeOut= 60
                # print urllib2.urlopen('http://api.macvendors.com/'+macv, timeout=TimeOut).read()
		mac = urllib2.urlopen('http://api.macvendors.com/'+macv, timeout=TimeOut).read()
        except Exception as inst:
                if "404" in str(inst) :
                        #print "Vendor not found"
			mac = "NOT-FOUND"
                else :
                        #print type(inst)
                        #print inst.args
                        #print inst
			mac="-inst-"
                pass

def channel_hopper():
	while True:
		try:
			channel = random.randrange(1,13)
			os.system("iw dev %s set channel %d" % (interface, channel))
			time.sleep(1)
		except KeyboardInterrupt:
			break

def signal_handler(signal, frame):
	p.terminate()
	p.join()
	sys.exit(0)

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Usage %s monitor_interface" % sys.argv[0]
		sys.exit(1)

	interface = sys.argv[1]
	p = Process(target = channel_hopper)
	p.start()
	signal.signal(signal.SIGINT, signal_handler)

	sniff(iface=interface,prn=sniffAP, store=0) #,count=10000)
