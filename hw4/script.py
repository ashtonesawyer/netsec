#!/usr/bin/python3

from scapy.all import *

filter = 'host 192.168.86.228 and host 192.168.86.167 and port 5000'
packets = sniff(offline="firmware.pcap", filter=filter, session=TCPSession)

loads = packets[Raw]

data = b''
special = (int(len(loads)/4) -1) * 4
for i in range(0,len(loads),4):
    if i == special:
       d = loads[i+2].load.split(b'\r\n')[-1]
       data += base64_bytes(d)
       break

    else:
        d = loads[i+2][Raw].load.split(b'\r\n')[-1] +  loads[i+3][Raw].load
        data += base64_bytes(d)

f = open("update", 'bw')
f.write(data)





