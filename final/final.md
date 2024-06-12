[[_TOC_]]

# Overview
[CVE-2020-11896](jsof-tech.com/wp-content/uploads/2020/06/JSOF_Ripple20_Technical_Whitepaper_June2020.pdf) is one 
of the Ripple20 bugs, a set of vulnerabilities found in the widely used Trek TCP/IP stack.
This particular vulnerability stems from a weak trim function that is called when the total length as given in the
IP header is smaller than the total available data. With fragmented IPv4-in-IPv4 tunneling, the sanity checks
can be passed and this trim function can cause a heap overflow when the total packet data is copied into a 
buffer that was allocated based on the incorrect length. If there's a listening UDP port on a device that uses the
Trek stack and if the UDP queue is not empty, then this heap overflow can lead to remote code execution. 

## Requirements
- IP protocol 4 (IP-in-IP)
- Fragmented UDP packets
- Inner IP packet has incorrect data length in the header
- UDP receive queue isn't empty

# Suricata Rule
The rule itself if simple. If it's an IPv4 packet with IP protocol 4 (IP-in-IP tunnelling), then check it with the lua script. 

```
alert ip any any -> any any (msg:"Tunnelling fragments -- CVE-2020-11896"; ip_proto:4; lua:cve-2020-11896.lua; sid: 11111111;)
```

## Script
The script starts with this `init` function. Every Suricata script needs an init function that follows
this format. The `needs[]` will change, but in this case we need to look at the entire packet (the header and 
the contents). 

```lua
function init (args)
        local needs = {}
        needs["packet"] = tostring(true) -- needs to inspect entire packet (incl. headers)
        return needs
end
```

The function that follows actually checks the packet has the following form:

```lua
function match(args)
    local packet = args["packet"]

    if (packet == criteria) then
        return 1
    end

    return 0
end
```
In this case, there are multiple steps to inspecting the packet:
1. Get to the inner IPv4 packet
2. Get UDP listed length
3. Get actual packet length
4. If listed length < actual length then return 1

### Inner Packet
The IP header will start with the IP version (4) and the length (generally 5) as nibbles, so 
should start with the hex byte 0x45. `string.find()` will return the first occurance within the
string, so we can start there. 
Then, because the IP header is  20 bytes, we know that the first byte of the 
inner packet's header will be 20 bytes after the 0x45.

```lua
   local outer = args["packet"]

    -- if it's empty then move on
    if outer == nil then
            return 0
    end

    local ip,e = string.find(outer, "\x45")
    local inner = string.sub(outer, ip+20)
```

The inner packet should also be IPv4, so we can check for the same
version/length as before. 

```lua
    if inner:byte(1) ~= 0x45 then
        return 0
    end
```

### UDP Listed Length
The UDP length field is the 5th and 6th bytes of the UDP header. 
So, it should be the 25th and 26th bytes of the inner IP packet. 
Lua doesn't seem to have a way to convert 2 bytes from a string to a number
in one go, so I converted them separately. It also probably would have made more sense
to bitshift the high byte rather than multiplying it, but it kept giving me an error, so
multiplication it is. 

```lua
    local len_str = inner:sub(25,26)
    local listed_len = tonumber(len_str:byte(1)) * 2^8 + tonumber(len_str:byte(2))
```

### Actual Length + Returning
A UDP header is 8 bytes long, so adding that to the 20 byte IPv4 header
means that the data starts on the 29th byte and it should go until the end of
the packet.

In practice, the `listed_len` and `real_len` should be exactly the same,
but for this particular vulnerability we only need to check if the `real_len` 
is larger. 

```lua
    local data = inner:sub(29)
    local real_len = data:len()

    if listed_len < real_len then
            return 1
    end

    return 0
```

### Full Script
```lua
function init (args)
        local needs = {}
        needs["packet"] = tostring(true) -- needs to inspect entire packet (incl. headers)
        return needs
end


function match(args)
        local outer = args["packet"]

        -- if it's empty then move on
        if outer == nil then
                return 0
        end

        -- start with IP version + len
        local ip,e = string.find(outer, "\x45")
        -- 20 bytes header, so inner packet should start at ip+20
        local inner = string.sub(outer, ip+20)


        -- Inner should also be IPv4
        if inner:byte(1) ~= 0x45 then
                return 0
        end

        -- length is bytes 5+6 of UDP header
        local len_str = inner:sub(25,26)
        -- convert 2-byte field from string to int
        local listed_len = tonumber(len_str:byte(1)) * 2^8 + tonumber(len_str:byte(2))

        -- 20 byte IPv4 header + 8 byte UDP header (+1 for 1-indexing)
        local data = inner:sub(29)
        local real_len = data:len()

        if listed_len < real_len then
                return 1
        end

        return 0
end
```

# Testing
There are two problems with this script that I can forsee causing false negatives:
1. It relies on the IP headers not using the options field
2. One of the MAC addresses in the Ethernet layer might have a 0x45 in it

The first problem is because if the header *does* use the options field, then the 5 in the 0x45 
will be different to account for the different header size. I don't see this being that much of a 
problem, however, as my understanding is that the options field isn't used often.

The second problem is because if a 0x45 byte shows up earlier in the packet than expected, then 
the calculations involing which bytes should be which fields will be thrown off. If this becomes a 
problem, a check could be added to the script that the 45 isn't within the first 14 bytes
(the length of an ethernet header). 

Barring these two problems, I am pretty confident that the rule will work because of the testing
that was done, described below.

## Generating Packets
I generated packets for `final.pcap` with the following script. Note that `bad_packet()` was
modified from the [original proof of concept code](https://github.com/0xkol/ripple20-digi-connect-exploit)

```py
from scapy.all import *

def num():
    return int(RandShort())

def bad_packet():
    port = num()

    inner = IP(dst='10.218.219.207', len=32)
    inner /= UDP(sport=port, dport=port, chksum=0, len=32-20)
    inner /= 'A' * 1000

    ip_id = int(RandShort())

    frag1 = IP(dst='10.218.219.207', frag=0, flags=1, proto=4, id=ip_id)
    frag1 /= bytes(inner)[:40]

    frag2 = IP(dst='10.218.219.207', frag=(40>>3), flags=0, proto=4, id=ip_id)
    frag2 /= bytes(inner)[40:]

    frag1.show()
    frag2.show()

    send(frag1)
    send(frag2)

def good_packet():
    port = num()

    packet = IP(dst='10.218.219.207')/IP(dst='10.218.219.207')/UDP(sport=port, dport=port, len=100)
    packet /= 'A' * 100
    packet.show()

    # this fragsize is semi-arbitrary --  it resulted in 2 fragments with some of the 
    # raw payload in the first and the rest in the second
    for f in fragment(packet, fragsize=80):
        f.show()
        send(f)

if __name__ == '__main__':
    port = num()

    bad_packet()
    good_packet()
    send(IP(dst='10.218.219.207')/UDP(sport=port, dport=port)/Raw(load=('A' * 100)))
    bad_packet()
```
The actual pcap was created using `tcpdump` to capture the packets sent by the script.
It has 7 packets in total, 6 of which are 3 fragmented packets, 2 of which are formed to trigger the rule. 

## Running Tests
I deleted suricata's `fast.log` before each of my tests to make it easy to see how many alerts were triggered for a 
particular run, and I used the `-S` flag with my rules file so that any other rules I might have in my
config file would be skipped and only the rule I was testing would run. 

```
 $ sudo suricata -i eth0 -S rule.rules                                     | $ sudo tcpreplay -i eth0 final.pcap
i: suricata: This is Suricata version 7.0.5 RELEASE running in SYSTEM mode |Actual: 7 packets (2530 bytes) sent in 0.296683 seconds
i: threads: Threads created -> W: 4 FM: 1 FR: 1   Engine started.          |Rated: 8527.6 Bps, 0.068 Mbps, 23.59 pps
                                                                           |Flows: 2 flows, 6.74 fps, 7 unique flow packets, 0 unique non-flow packets
                                                                           |Statistics for network device: eth0
                                                                           |        Successful packets:        7
                                                                           |        Failed packets:            0
                                                                           |        Truncated packets:         0
                                                                           |        Retried packets (ENOBUFS): 0
                                                                           |        Retried packets (EAGAIN):  0
----------------------------------------------------------------------------------------------------------------------------------------------------------
 $ cat /var/log/suricata/fast.log
06/11/2024-16:50:22.466452  [**] [1:11111111:0] Tunnelling fragments -- CVE-2020-11896 [**] [Classification: (null)] [Priority: 3] {IP-in-IP} 172.22.141.10
2:0 -> 10.218.219.207:0
06/11/2024-16:50:22.714514  [**] [1:11111111:0] Tunnelling fragments -- CVE-2020-11896 [**] [Classification: (null)] [Priority: 3] {IP-in-IP} 172.22.141.10
2:0 -> 10.218.219.207:0
```

