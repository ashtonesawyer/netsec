# Network Security
This is a backup of my homework from Network Securyty (CS496 - Spring 24) that was originally 
hosted on GitLab. The main markdown file in each folder is the walkthrough of what
I did for the homework. 

Below is a breif description of the different homeworks.

## HW1 - VM Setup
I set up a Kali linux VM using Hyper-V

## HW2 - Packet Capture
I created packet dumps using `tcpdump` with different BPF filters. 
The format for each dump was to be a full data dump without link layer headers, 
in hex and ascii, and with Unix styled epoch style timestamps. 

## HW3 - Hacking WiFi
I used `bettercap` to find clients on a network and perform and capture a deauth 
attack and `hashcat` to crack the password. I then used `nmap` to scan the network and 
find an RTSP stream to connect to. 

## HW4 - `scapy`
I used `scapy` to extract a firmware update from a packet capture
that I could then further explore. 

## HW5 - Fuzzing
I used `afl-net` to fuzz specific versions of Live555 and Dnsmasq. 

## Final - Suricata
I created a Suricate rule for Ripple20's CVE-2020-11896. This involved writing a Lua script and 
creating a packet capture to test with using `scapy`. 
