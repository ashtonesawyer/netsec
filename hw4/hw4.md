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
 $ file /bin/busybox
busybox: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-mipsel-sf.so.1, no section header
```
This is a MIPS32 system

## OS
```
 $ cat /etc/os-release
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2024.1"
VERSION="2024.1"
VERSION_CODENAME=kali-rolling
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31"
```

It's running Kali 2024.1

## Users
```
 $ ls /usr
       bin/                    libexec/
       games/                  local/
       i686-w64-mingw32/       sbin/
       include/                share/
       lib/                    src/
       lib32/                  x86_64-w64-mingw32/
       lib64/                  x86_64-w64-mingw32ucrt/

 $ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:102:MariaDB Server,,,:/nonexistent:/bin/false
tss:x:102:103:TPM software stack,,,:/var/lib/tpm:/bin/false
systemd-coredump:x:992:992:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:991:991:systemd Time Synchronization:/:/usr/sbin/nologin
redsocks:x:103:104::/var/run/redsocks:/usr/sbin/nologin
rwhod:x:104:65534::/var/spool/rwho:/usr/sbin/nologin
_gophish:x:105:106::/var/lib/gophish:/usr/sbin/nologin
iodine:x:106:65534::/run/iodine:/usr/sbin/nologin
messagebus:x:107:107::/nonexistent:/usr/sbin/nologin
miredo:x:108:65534::/var/run/miredo:/usr/sbin/nologin
redis:x:109:110::/var/lib/redis:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mosquitto:x:111:112::/var/lib/mosquitto:/usr/sbin/nologin
tcpdump:x:112:114::/nonexistent:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
_rpc:x:114:65534::/run/rpcbind:/usr/sbin/nologin
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
avahi:x:117:118:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
stunnel4:x:990:990:stunnel service system account:/var/run/stunnel4:/usr/sbin/nologin
Debian-snmp:x:118:119::/var/lib/snmp:/bin/false
_gvm:x:119:120::/var/lib/openvas:/usr/sbin/nologin
speech-dispatcher:x:120:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
sslh:x:121:122::/nonexistent:/usr/sbin/nologin
postgres:x:122:123:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
pulse:x:123:124:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
inetsim:x:124:126::/var/lib/inetsim:/usr/sbin/nologin
geoclue:x:125:127::/var/lib/geoclue:/usr/sbin/nologin
sddm:x:126:128:Simple Desktop Display Manager:/var/lib/sddm:/bin/false
polkitd:x:988:988:polkit:/nonexistent:/usr/sbin/nologin
rtkit:x:127:129:RealtimeKit,,,:/proc:/usr/sbin/nologin
sawyeras:x:1000:1000:Ash,,,:/home/sawyeras:/usr/bin/zsh
fwupd-refresh:x:987:987:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
freerad-wpe:x:128:132::/etc/freeradius-wpe:/usr/sbin/nologin
Debian-exim:x:129:133::/var/spool/exim4:/usr/sbin/nologin
beef-xss:x:130:135::/var/lib/beef-xss:/usr/sbin/nologin
xrdp:x:131:136::/run/xrdp:/usr/sbin/nologin
```

There aren't any human users, but there are some services.
