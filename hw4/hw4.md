[[_TOC_]]

# Getting the update
## Wireshark
Looking through the pcap in Wireshark showed multiple packets with the payload `GET /download?name=firmware.bin...`.
These packets were from `192.168.86.167` to `192.168.86.228:5000`. 

## Scapy
Initialize:

```py
from scapy.all import *
```

Loading the packets:

```py
filter = 'host 192.168.86.228 and host 192.168.86.167 and port 5000'
packets = sniff(offline="firmware.pcap", filter=filter, session=TCPSession)
```

Looking at some of the packetes shows that the ones with the actual update 
data have a Raw layer, so we can filter down farther. 

```py
loads = packets[Raw]
```

Looking at these packets shows a general patter of GET, OK, Content-Type + first part of data,
and then the second part of the data, with that data base64 encoded. 
The first packet with the relevant data starts with other information, which needs to be trimmed out, and
then it has to be combined with the data from the next packet before it can be base64 decoded.

```py
data = b''
for i in range(0,len(loads),4):
    d = loads[i+2][Raw].load.split(b'\r\n')[-1] + loads[i+3][Raw].load
    data += base64_bytes(d)
```

This throws an indexing error, which can be ignored, but I decided to better handle the end of the capture.

```py
data = b''
special = (int(len(loads)/4) -1) * 4
for i in range(0,len(loads),4):
    if i == special:
       d = loads[i+2].load.split(b'\r\n')[-1]
       data += base64_bytes(d)
       break

    else:
        d = loads[i+2][Raw].load.split(b'\r\n')[-1] + loads[i+3][Raw].load
        data += base64_bytes(d)

f = open("update", 'bw')
f.write(data)

```

# The Update

```
 $ binwalk update

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
48            0x30            Unix path: /dev/mtdblock/2
96            0x60            LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 4438276 bytes
302958        0x49F6E         MySQL MISAM index file Version 4
1441888       0x160060        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2208988 bytes, 1159 inodes, blocksize: 262144 bytes, created: 2019-08-06 21:20:37

 $ binwalk -Me update
Scan Time:     2024-05-28 15:39:23
Target File:   /home/sawyeras/update
MD5 Checksum:  7aa6a7ebcbd98ce19539b668ff790655
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
48            0x30            Unix path: /dev/mtdblock/2
96            0x60            LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 4438276 bytes
302958        0x49F6E         MySQL MISAM index file Version 4

...

Scan Time:     2024-05-28 15:39:24
Target File:   /home/sawyeras/_update.extracted/60
MD5 Checksum:  24d29d1dc329ae3314c4899a5e41fe83
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1040          0x410           Flattened device tree, size: 4729 bytes, version: 17
3708304       0x389590        CRC32 polynomial table, little endian
3734583       0x38FC37        Intel x86 or x64 microcode, sig 0x03000000, pf_mask 0x01, 2088-18-20, rev 0x3baa3000, size 136
3869788       0x3B0C5C        xz compressed data
3902428       0x3B8BDC        Unix path: /lib/firmware/updates/4.14.95
3921700       0x3BD724        Unix path: /sys/firmware/devicetree/base
3922521       0x3BDA59        Unix path: /sys/firmware/fdt': CRC check failed
3931117       0x3BFBED        Neighborly text, "neighbor table overflow!solicit"
3950660       0x3C4844        Neighborly text, "NeighborSolicitsports"
3950680       0x3C4858        Neighborly text, "NeighborAdvertisements"
3953602       0x3C53C2        Neighborly text, "neighbor %.2x%.2x.%pM lost rename link %s to %s"
4280320       0x415000        ELF, 32-bit LSB MIPS64 shared object, MIPS, version 1 (SYSV)
4437760       0x43B700        ASCII cpio archive (SVR4 with no CRC), file name: "dev", file name length: "0x00000004", file size: "0x00000000"
4437876       0x43B774        ASCII cpio archive (SVR4 with no CRC), file name: "dev/console", file name length: "0x0000000C", file size: "0x00000000"
4438000       0x43B7F0        ASCII cpio archive (SVR4 with no CRC), file name: "root", file name length: "0x00000005", file size: "0x00000000"
4438116       0x43B864        ASCII cpio archive (SVR4 with no CRC), file name: "TRAILER!!!", file name length: "0x0000000B", file size: "0x00000000"


Scan Time:     2024-05-28 15:39:25
Target File:   /home/sawyeras/_update.extracted/_60.extracted/console
MD5 Checksum:  d41d8cd98f00b204e9800998ecf8427e
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

## Architecture

```
 $ cd _update.extracted/squashfs-root/
 $ file bin/busybox
bin/busybox: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-mipsel-sf.so.1, no section header

```
This is a MIPS32 system

## OS
```
 $ cat etc/os-release
NAME="OpenWrt"
VERSION="18.06.2"
ID="openwrt"
ID_LIKE="lede openwrt"
PRETTY_NAME="OpenWrt 18.06.2"
VERSION_ID="18.06.2"
HOME_URL="http://openwrt.org/"
BUG_URL="http://bugs.openwrt.org/"
SUPPORT_URL="http://forum.lede-project.org/"
BUILD_ID="r7676-cddd7b4c77"
LEDE_BOARD="ramips/rt288x"
LEDE_ARCH="mipsel_24kc"
LEDE_TAINTS=""
LEDE_DEVICE_MANUFACTURER="OpenWrt"
LEDE_DEVICE_MANUFACTURER_URL="http://openwrt.org/"
LEDE_DEVICE_PRODUCT="Generic"
LEDE_DEVICE_REVISION="v0"
LEDE_RELEASE="OpenWrt 18.06.2 r7676-cddd7b4c77"
```

It's running OpenWrt 18.06.2

## Users
```
 $ ls usr
       bin/       libexec/       share/
       lib/       sbin/

 $ cat etc/passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
```

There aren't any human users, but there are some services.

### Cracking `root` Password
```
 $ head etc/shadow
root:$6$19yJir3t$DKemu8nRjxvuPbDZdZcdtsJiiVd7zAXN7Q63.eepYT.R0LqsDMYCzwetEO58sPROWiVfhY1Aeu3O3awr57fv50:17994:0:99999:7:::
...

 $ echo -n '$6$19yJir3t$DKemu8nRjxvuPbDZdZcdtsJiiVd7zAXN7Q63.eepYT.R0LqsDMYCzwetEO58sPROWiVfhY1Aeu3O3awr57fv50' > crackme
 $ hashcat -O crackme /usr/share/wordlists/fasttrack.txt
...

Dictionary cache built:
* Filename..: /usr/share/wordlists/fasttrack.txt
* Passwords.: 262
* Bytes.....: 2430
* Keyspace..: 262
* Runtime...: 0 secs

$6$19yJir3t$DKemu8nRjxvuPbDZdZcdtsJiiVd7zAXN7Q63.eepYT.R0LqsDMYCzwetEO58sPROWiVfhY1Aeu3O3awr57fv50:P@55w0rd!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$19yJir3t$DKemu8nRjxvuPbDZdZcdtsJiiVd7zAXN7Q63.ee...57fv50
Time.Started.....: Thu May 30 17:22:55 2024 (0 secs)
Time.Estimated...: Thu May 30 17:22:55 2024 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/fasttrack.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      944 H/s (3.07ms) @ Accel:256 Loops:64 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 256/262 (97.71%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 0/262 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidate.Engine.: Device Generator
Candidates.#1....: Spring2017 -> monkey
Hardware.Mon.#1..: Util: 35%

Started: Thu May 30 17:22:53 2024
Stopped: Thu May 30 17:22:57 2024
```
