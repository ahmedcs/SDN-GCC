# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation."""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import *
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
#from ryu.lib.ofproto import inet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet.tcp import TCPOption
from ryu.lib.packet.tcp import TCPOptionWindowScale
import time
from threading import Timer
from socket import *
from uuid import getnode as get_mac
from ryu.lib.mac import *
import binascii
from struct import *
import fcntl, socket, struct
import math
from datetime import datetime
import subprocess
import numpy as np
from numpy import *
import cStringIO
import StringIO
from StringIO import StringIO

sampleinterval=0.001
RTT = 500 #500
Capacity = (1*1000*1000*1000)
AMSS = 1000 #1000
Buffer = 85300
BDP=Capacity/8 * RTT *  1/1000000
pipebuffer = math.ceil((BDP + Buffer) / AMSS)
initcwnd = 10
mainport = None
searchstr = ' '
maindpid = None
totalmarks = 0
dstlist = []

def mac_to_binary(mac):
    addr = ''
    temp = mac.replace(':', '')
    #for i in range(0, len(temp), 2):
    #    addr = ''.join([addr, struct.pack('H', int(temp[i: i + 2], 16))])
    #return addr
    return binascii.unhexlify(temp)

def getHwAddr(ifname):
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    	return ':'.join(['%02x' % ord(char) for char in info[18:24]])


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
	self.timeron = False
	self.count = 0
	self.lastcall = None
	self.totalcount = 0
	self.port_num_to_name = {}
	self.port_marks = {}
	self.port_totalmarks = {}
	self.mac_to_port = {}
	self.dstsrc_table = {}
	self.ip_to_port = {}
        self.dstsrc_iptable = {}



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features reply to install table miss flow entries."""
	global maindpid
        dpid = ev.msg.datapath_id
	#datapath = ev.msg.datapath
        #[self.install_table_miss(datapath, n) for n in [0, 1]]

	self.dstsrc_iptable.setdefault(dpid, {})
	self.port_marks.setdefault(dpid, {})
	self.port_totalmarks.setdefault(dpid, {})
	self.ip_to_port.setdefault(dpid, {})
	self.mac_to_port.setdefault(dpid, {})
        self.dstsrc_table.setdefault(dpid, {})
	self.port_num_to_name.setdefault(dpid, {})
	maindpid = dpid
	self.getswitchports(dpid)

    def install_table_miss(self, datapath, table_id):
        """Create and install table miss flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        output = parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        write = parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,[output])
        instructions = [write]
        flow_mod = self.create_flow_mod(datapath, 0, 0, 0, table_id, empty_match, instructions)
        datapath.send_msg(flow_mod)

    def getswitchports(self, dpid):
	"""get port information from switch having id of dpid."""
	global mainport,searchstr
	p = subprocess.Popen("ssh root@switch ovs-ofctl dump-ports-desc switch | grep '[0-9](' | awk 'BEGIN { FS = \")\" } ; { print $1 }' |  awk 'BEGIN { FS = \"(\" } ; { print $1,$2 }'", shell=True, stdout=subprocess.PIPE)
	str1 = StringIO(p.stdout.read())
	ports = np.genfromtxt(str1, usecols=(0,1), delimiter=' ', dtype=None, unpack=False)
	for port in ports:
		#print port[0], port[1]
		self.port_num_to_name[dpid][port[0]] = port[1]
	print self.port_num_to_name[dpid]

	for port in self.port_num_to_name[dpid]:
		portname = self.port_num_to_name[dpid][port]
		str1= "tc -p -s -d  qdisc show dev %s | grep  marked | grep -Eo '[0-9]{1,15} e' | sed -e 's/\(e\)*$//g'" % portname
		if portname == 'p1p2':
			mainport=port
			searchstr=str1
		print str1
		p = subprocess.Popen("ssh root@switch %s" % str1, shell=True, stdout=subprocess.PIPE)
		string = StringIO(p.stdout.read())
		marks=0
		try:
		 	marks=int(string.getvalue())
   		except ValueError:
       			pass
		print port, ":", portname, " marked=", marks

    def sendip(self, dstip, srcip,  payload=0):
    	"""Send raw IP packet on interface."""

	#create a raw socket
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()

	# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
	# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	# now start constructing the packet
	packet = '';

	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = min(65535, payload)   #Id of this packet is the number of marks 54321
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = 143
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( srcip )   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( dstip)

	ip_ihl_ver = (ip_ver << 4) + ip_ihl

	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

  	# final full packet - syn packets dont have any data
	packet = ip_header #+ payload
    	#print datetime.now(), '-> Sent marking packet to: ', dstip, ' message : ', packet

	#Send the packet finally - the port specified has no effect
	s.sendto(packet, (dstip , 0 ))    # put this in a loop if you want to flood the target
	s.close()
	#print 'Sent marking packet to: ', dstip, ' from: ', srcip, ' with marking= ', payload

    def check_connections(self):
	global pipebuffer, RTT, totalmarks, searchstr

	if searchstr == ' ':
		Timer(sampleinterval, self.check_connections, ()).start()
		return
	p = subprocess.Popen("ssh root@switch %s" % searchstr, shell=True, stdout=subprocess.PIPE)
	string = StringIO(p.stdout.read())
	currentmarks=0
	try:
		currentmarks=int(string.getvalue())
   	except ValueError:
       		pass
	marks = max(0, currentmarks - totalmarks)
	#print 'checking RED at ', datetime.now(), 'marks: ', marks
	if marks > 0:
	     #for dpid in self.ip_to_port:
		 #for dst in self.ip_to_port[dpid].keys():
			#print 'checking RED at ', datetime.now(), ' marks: ', marks, 'port: ', self.ip_to_port[dpid][dst], ':', mainport
			#if self.ip_to_port[dpid][dst] == mainport:
        	dstnum = len(dstlist)
        	totalsrc = 0
        	for dst in dstlist:
			srclist = [src for (src, dst_) in self.dstsrc_iptable.get(maindpid).items()  if dst_ == dst]
			totalsrc = totalsrc + len(srclist)
	        if totalsrc > 0:
    			for dst in dstlist:
    				srclist = [src for (src, dst_) in self.dstsrc_iptable.get(maindpid).items()  if dst_ == dst]
    				srcnum = len(srclist)
    				print datetime.now(), 'port: ', mainport , 'caused ECN ->  dst: ', dst, 'src: ', srclist, ' totalmarks: ', totalmarks, 'newmarks: ', marks
				if srcnum > 0:
	    				amount = marks/ srcnum #totalsrc
	    				for src in srclist:
    				        	self.sendip(src, dst, amount)
	totalmarks = currentmarks
	Timer(sampleinterval, self.check_connections, ()).start()


    def send_desc_stats_request(self, datapath):
	ofp_parser = datapath.ofproto_parser
	req = ofp_parser.OFPDescStatsRequest(datapath)
	datapath.send_msg(req)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

	match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
	in_port = msg.in_port
	dpid = datapath.id

        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: #or eth.ethertype != ether_types.ETH_TYPE_IP or eth.ethertype != ether_types.ETH_TYPE_ARP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

	dstip=""
	srcip=""
	try:
		ip = pkt.get_protocol(ipv4.ipv4)
		arph = pkt.get_protocol(arp.arp)
		if ip is None and arph is None:
			return
		if ip is not None:
			dstip = ip.dst
                        srcip = ip.src
			if not srcip or srcip == '255.255.255.255': #or not dstip or dstip == '255.255.255.255':
			   return
			#print ip

		elif arp is not None:
		        dstip = arph.dst_ip
                        srcip = arph.src_ip
			if not srcip or srcip == '255.255.255.255' or not dstip or dstip == '255.255.255.255':
			   return
			#print arph


		#if self.dstsrc_iptable[dpid].get(dstip, None) is None:
		#	self.dstsrc_iptable[dpid][dstip]=0
		self.dstsrc_iptable[dpid][srcip]=dstip

		#if self.ip_to_port[dpid].get(srcip, None) is None:
		#	self.ip_to_port[dpid][srcip]=0
		self.ip_to_port[dpid][srcip] = msg.in_port

		if msg.in_port == mainport  and srcip is not None:
			if srcip not in dstlist:
				dstlist.append(srcip)

		if self.port_marks[dpid].get(msg.in_port, None) is None:
			self.port_marks[dpid][msg.in_port]=0

		if self.port_totalmarks[dpid].get(msg.in_port, None) is None:
			self.port_totalmarks[dpid][msg.in_port]=0

		#print 'srcip: ', srcip, 'srcmac: ', src, 'dstip: ', dstip, 'dstmac: ', dst, 'portnum: ', msg.in_port

		if self.timeron == False:
			print 'timer started at ', datetime.now()
			Timer(sampleinterval, self.check_connections, ()).start()
			self.timeron=True

	except msg:
            print 'Not an IP packet Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            return

	if self.dstsrc_table[dpid].get(dst, None) is None:
		self.dstsrc_table[dpid][dst]=0
	self.dstsrc_table[dpid][src]=dst

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port


	if self.port_num_to_name[dpid].get(msg.in_port, None) is None:
		self.port_num_to_name[dpid][msg.in_port]=None

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        	data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
	msg = ev.msg
	dp = msg.datapath
	ofp = dp.ofproto
	if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
		reason = 'IDLE TIMEOUT'
	elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
		reason = 'HARD TIMEOUT'
	elif msg.reason == ofp.OFPRR_DELETE:
		reason = 'DELETE'
	elif msg.reason == ofp.OFPRR_GROUP_DELETE:
		reason = 'GROUP DELETE'
	else:
		reason = 'unknown'
	self.logger.debug('OFPFlowRemoved received: '
	'match=%s cookie=%d priority=%d reason=%s '
	'duration_sec=%d duration_nsec=%d '
	'idle_timeout=%d packet_count=%d byte_count=%d',
	msg.match, msg.cookie, msg.priority, reason,
	msg.duration_sec, msg.duration_nsec,
	msg.idle_timeout, msg.packet_count,
	msg.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
