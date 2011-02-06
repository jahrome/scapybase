#!/usr/bin/env python
#
#   scapybase.py - 802.11 monitor AP based on scapy
#
#   Copyright (C) 2010 Jerome Marty (jahrome11@gmail.com)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os, sys, time, datetime
from scapy.all import *


# User serviceable parts
wlan_iface = 'wlan0'
ssid = ['default']
channel = 1
beacon_interval = 100 # milliseconds
all_probes = False # respond to all probes
tap_iface = 'sb0'
tap_address = '192.168.5.1'
verbose = True


wl_mac = str2mac(get_if_raw_hwaddr(wlan_iface)[1])
conf.iface = wlan_iface
os.system("iwconfig " + wlan_iface + " mode monitor channel " + str(channel))
# BPF socket level filter to avoid reading our frames
bpf_filter = 'not wlan addr2 ' + wl_mac
pks = conf.L2socket(iface=wlan_iface, filter=bpf_filter, nofilter=0, type=ETH_P_ALL)


# XXX No summary on Packet, create PacketList as a workaround
def print_summary(pkt):
    p = plist.PacketList([])
    p.append(pkt)
    p.summary()


def send_packet(pkt):
    pks.send(pkt)
    if verbose:
        print_summary(pkt)


while (1):
    rdpipe, wrpipe = os.pipe()
    rdpipe = os.fdopen(rdpipe)
    wrpipe = os.fdopen(wrpipe,"w")

    pid=1
    try:
        pid = os.fork()
        if pid == 0:
            rdpipe.close()
            fd_tap = os.open('/dev/net/tun', os.O_RDWR)
            ifs = ioctl(fd_tap, 0x400454ca, struct.pack("16sH", tap_iface, 0x1002))
            os.system("ifconfig " + tap_iface + " " + str(tap_address) + " up")

            pid2 = os.fork()
            if pid2 == 0:
                while 1:
                    inp, out, err = select([pks],[],[])
                    if len(inp) == 0:
                        break
                    r = pks.recv(MTU)
                    if not r.haslayer(Dot11):
                        continue

                    if verbose:
                        print_summary(r)

                    if r.type == 0x00: # Management frame
                        if r.subtype == 0x04: # Probe request
                            # XXX Respond to broadcast probes
                            if len(r[Dot11ProbeReq].info) != 0:
                                if r[Dot11ProbeReq].info in ssid or all_probes:
                                    essid = str(r[Dot11ProbeReq].info).strip()
                                    wrpipe.write(essid + '\n')
                                    wrpipe.flush()

                                    # XXX Timestamp are truncated to 32 bits in real frame, why ?
                                    resp = RadioTap()/Dot11(addr1=r.addr2, addr2=wl_mac, addr3=wl_mac, SC=r.SC)/ \
                                        Dot11ProbeResp(timestamp=long(time.time()*10**6), beacon_interval=beacon_interval,
                                            cap="short-slot+ESS")
                                    # Copy tagged parameters circumventing incorrect parsing of 802.11 frame with radiotap and FCS
                                    # see http://trac.secdev.org/scapy/ticket/109
                                    resp = resp/Dot11Elt(str(r[Dot11Elt])[:-4])/ \
                                        Dot11Elt(ID="DSset", info=str("%02d"%channel).decode('hex'))
                                    send_packet(resp)

                        elif r.subtype == 0x0b: # Authentication
                            resp = RadioTap()/ \
                                Dot11(addr1=r.addr2, addr2=wl_mac, addr3=wl_mac, SC=r.SC)/ \
                                Dot11Auth(seqnum=r[Dot11Auth].seqnum+1)
                            send_packet(resp)

                        elif r.subtype == 0x00: # Association Request
                            resp = RadioTap()/ \
                                Dot11(addr1=r.addr2, addr2=wl_mac, addr3=wl_mac, SC=r.SC)/ \
                                Dot11AssoResp(cap="short-slot+ESS", AID=1)/ \
                                Dot11Elt(str(r[Dot11Elt])[:-4]) # XXX http://trac.secdev.org/scapy/ticket/109
                            send_packet(resp)

                    elif r.type == 0x02: # Data frame
                        if r.subtype == 0x00: # Avoid Null Function frames
                            # Send received data to tap interface
                            data = Ether(src=r[Dot11].addr2, dst=r[Dot11].addr3, type=r[SNAP].code)/r[SNAP].payload
                            os.write(fd_tap, str(data))

            elif pid2 < 0:
                print "Fork error"
            else:
                while 1:
                    inp, out, err = select([fd_tap],[],[])
                    if fd_tap in inp:
                        data = os.read(fd_tap, MTU)
                        p = Ether(data)
                        pkt = RadioTap()/Dot11(FCfield=0x02, addr1=p.dst,addr2=wl_mac,addr3=wl_mac)/ \
                            LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/ \
                            SNAP(code=p[Ether].type)/ \
                            p[Ether].payload
                        send_packet(pkt)

        elif pid < 0:
            print "Fork error"
        else:
            wrpipe.close()
            if verbose:
                print "\nAccess Point with BSSID %s started.\n" % (wl_mac)

            while 1:
                inp, out, err = select([rdpipe],[],[],0)
                if rdpipe in inp:
                    new_ssid = rdpipe.readline().strip()
                    if all_probes and new_ssid not in ssid:
                        ssid.append(new_ssid)
                        if verbose:
                            print "\n*** Beaconing new SSID: %s ***\n" % (new_ssid)

                pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=wl_mac,addr3=wl_mac)/ \
                    Dot11Beacon(timestamp=long(time.time()*10**6), beacon_interval=beacon_interval, cap="short-slot+ESS")/ \
                    Dot11Elt(ID="SSID",info=ssid)/Dot11Elt(ID="Rates",info='\x02\x04\x0b\x16')/ \
                    Dot11Elt(ID="ESRates",info="\x0c\x12\x18\x60\x6c")/ \
                    Dot11Elt(ID="DSset",info=str("%02d"%channel).decode('hex'))

                [pks.send(i) for i in pkt]
                time.sleep(float(beacon_interval)/1000)

    except KeyboardInterrupt:
        break

    finally:
        if pid == 0:
            print "Got Ctrl-C, exiting."
            os.close(fd_tap)
            os._exit(0)
