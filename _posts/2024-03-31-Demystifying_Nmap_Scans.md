---
title: "Demystifying Nmap Scans: A Deep Dive into Network Exploration"
date: 2024-03-31 23:00:00 +0530
categories: [Blogging, Writeup, CyberSec]
tags: [Blogging, Tutorial, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/nmap.png
  lqip: data:image/png;base64,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
--- 
## Introdution
Nmap, also known as the Network Mapper, is a free and open-source tool that helps IT professionals uncover the secrets of their network as well as for security auditing. It is like a flashlight that allows network discover, to see which devices are connected, what services are running on those devices (like web servers or email), and even what operating systems they are using (Windows, Linux, etc.). Nmap achieves this by sending specially crafted messages or packets across the network and analysing the responses.
Nmap is not just for discovery; it is also a versatile tool for network management. Network administrators use it to keep track of devices on their network (inventory), schedule updates for services, and even monitor if devices or services are up and running. Nmap is designed for large networks, it can also be used to scan a single computer.
## Why do a “network scanning”?
Networking scanning is vital process which gives a deep view on inventory of what system and services are available in network. It allows maintaining a healthy secure and managed network.
Enabling network administrators and security professional to gain a clear understating of their network to proactively identify and address any potential vulnerabilities, unauthorized devices and services that can be a point of entry for attackers.
Remember, it is crucial to only scan networks with proper authorization.

## How Nmap Works?
Imagine your network as a neighbourhood with multiple houses (devices). Nmap acts like a curious inspector who wants to know what is going on. But instead of knocking on doors directly, Nmap sends out special messages called packets. These packets travel through the network cables, reaching the different devices. By analysing how the devices respond to these packets, Nmap gathers information about them. 
Let us get more deeper by breaking down the concept of crafting packet and response analysis. 

### Crafting Messages (Packets):
Think of packets as little notes Nmap writes. These notes can be different depending on what Nmap wants to know. Here are some common types:
1.	__Delivery Attempt (TCP SYN packets):__ This is like sending a note to a house (device) saying, "Hi! I am interested, can we chat?" In the world of computers, this initiates a handshake to establish a connection. By analysing the response, Nmap can determine if the "door" (port) on the device is open (willing to chat) or closed (no answer).

2.	__Quick Check (UDP packets):__ Imagine throwing a pebble at a window (port) to see if someone's home. UDP packets are quicker than TCP packets, but they do not wait for a response. If a response comes back, it suggests an open port for a service like online gaming.

3.	__Simple Ping (ICMP Echo Request):__ This is like calling out, "Hello? Is anyone there?" A ping packet is used to see if a device is even switched on and "listening" on the network.

### Understanding the Responses:
Once Nmap sends its packets, it carefully listens to the replies from the devices. Here is what it is trying to understand:
1.	__Open or Closed Door (Port Status):__ Based on the response, Nmap can tell if a port on a device is open (like an open door - ready to communicate), closed (no answer), filtered (maybe blocked by a security guard - firewall), or unreachable (the house might be empty - device is off).

2.	__Who's Living There? (Service Identification):__ Sometimes, the response from an open port reveals clues about the service running on that port (like a name tag on the door). For instance, a specific response might indicate a web server or an email service.

3.	__What Kind of House? (Operating System Detection):__ Nmap analyses various details in the response, like how the device responds to certain requests or the way it formats its messages. This can provide hints about the operating system running on the device (like the architectural style of the house), but it is not always foolproof.

## Back to Networking Basics | Explaining TCP and UDP Connections. 
To really explain the handshake, we would need to talk a little more about how computers talk on networks, like how they break information into pieces and make sure everything arrives safely.
### TCP (Transmission Control Protocol):
Imagine TCP as a reliable postal service for your computer. It guarantees data delivery in order and without errors. Unlike throwing a message in a bottle, TCP ensures the recipient gets it and acknowledges receipt.
### Packets and Sequence Numbers:
Data on a network travel in small chunks called packets. TCP assigns a sequence number to each packet it sends. This helps the receiver order the packets correctly and identify any missing ones.
### The 3-Way Handshake:
TCP handshake, also known as the three-way handshake, is a fundamental process in establishing a reliable connection between two devices on a network using the Transmission Control Protocol (TCP). It ensures both devices are synchronized and ready to exchange data accurately.
1.	__Client initiates connection (SYN):__ The client, wanting to communicate with a server, sends a segment with the SYN flag set. This flag signifies the client's intent to initiate communication and includes an initial sequence number the client will use for data packets.
2.	__Server acknowledges and synchronizes (SYN-ACK):__ Upon receiving the SYN packet, the server acknowledges the connection request by sending a segment with both SYN and ACK flags set. The SYN flag indicates the server's readiness to connect, and the ACK flag acknowledges the client's sequence number. The server also includes its own initial sequence number in this packet.
3.	__Client acknowledges server (ACK):__ Finally, the client sends a segment back with just the ACK flag set, acknowledging the server's sequence number and completing the handshake.

![img-description](/assets/img/posts/nmap/1.png) _TCP handshake_

By exchanging these packets, both client and server establish synchronized sequence numbers for tracking data packets and ensuring reliable data exchange.
TCP handshake acts like a virtual handshake between devices, confirming their readiness to communicate before any data is transferred. This ensures a reliable and orderly flow of information.

>TCP connections are full duplex, meaning data can flow in both directions simultaneously.
{: .prompt-info }

>The handshake is used for both connection establishment and termination (with FIN flags).
{: .prompt-info }

### User Datagram Protocol:
UDP (User Datagram Protocol), is like a fast courier service for your computer. Unlike TCP (Transmission Control Protocol), which acts like a reliable postal service, UDP prioritizes speed over guaranteed delivery. 

1.	__No Connections:__  As mentioned in above analogy, throwing a pebble is a fast way to see if someone's home, UDP packets transmits datagram (packets) straight to the target device without setting a connection. As UDP do not waste time establishing a connection, making them efficient for tasks that need a fast response, like checking if a service is available.
2.	__No Waiting for Response:__ Like how you would not wait forever for someone to answer the window, UDP does not wait for an acknowledgement. It simply sends the data (the pebble) and moves on. It does not care if someone is there to catch it (receive the packet).
3.	__Open Port:__ If you see a light turn on inside the house (like a response coming back), it indicates the "window" (port) is open and someone is there (service is available). This is useful for applications like online gaming, where finding available servers quickly is important. Here is how it relates to ports:
    - Imagine the house is a computer, and each window represents a different service running on that computer.
    - The port number is like the address of that specific window.
    - Throwing a pebble (UDP packet) at a specific window (port) is like checking if that service is available.
    - If a response comes back (light turns on), it suggests the service is up and running on that port.

![img-description](/assets/img/posts/nmap/2.png) _UDP dataframe_

## Inital Scan:

Now that we have covered some fundamental network concepts, let us delve deeper into Nmap scanning. To illustrate, we will target `scanme.nmap.org` a learning resource created by Fyodor (Gordon Lyon). 

The basic command to being with nmap is `nmap <target>, where target can be an IP address, domain, or a range of address, for example:
```bash
nmap scanme.nmap.org
```

The above command will direct nmap to scan default 1000 most used ports of our target scanme.nmap.org. The scan result may include well known ports like 21(FTP),22(SSH),80(HTTP), 443(HTTPS), and many other ports that are frequently targeted by attackers. The key idea is to use nmap to identify which of these ports are open on a target device revelling what services are running and any potential vulnerability that can be exploited. 

```bash
┌──(kasyap㉿Brahma)-[~]
└─$ nmap scanme.nmap.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-01 15:20 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
25/tcp    filtered smtp
80/tcp    open     http
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
9929/tcp  open     nping-echo
31337/tcp open     Elite

Nmap done: 1 IP address (1 host up) scanned in 20.62 seconds
```
This basic scan provides minimal details. To gather more information, such as operating system or service version, additional flags can be used. 

For example, the `-sV` flag reveals version details. We will explore more advanced flags later.

```bash
┌──(kasyap㉿Brahma)-[~]
└─$ nmap scanme.nmap.org -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-01 16:13 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
25/tcp    filtered smtp
80/tcp    open     http        Apache httpd 2.4.7 ((Ubuntu))
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
9929/tcp  open     nping-echo  Nping echo
31337/tcp open     tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.90 seconds
```

## Interpreting Scan Results: 

Interpreting Nmap scan results is like deciphering a coded message. By analysing the scanned ports, their open or closed state, and the services running on those ports, along with any version information, you can paint a picture of what is running on a device. This can reveal valuable information such as the operating system, potential vulnerabilities, and what services are accessible on the network. By piecing together these details, you gain a deeper understanding of the network's security posture.  

Here are some key considerations. 

### Port States:
- __Open ports:__ Signifying active services listening for connections. Finding these is often the primary goal of port scanning. Security-conscious individuals understand that each open port is an avenue for attack.
- __Closed ports:__ while not actively used, can indicate potential services that could be deployed.
- __Filtered ports:__ Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated firewall device, router rules, or host-based firewall software.
- __Unfiltered ports:__ The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed.

### Services and versions:
It is crucial to identify the services running and their versions on open ports. This enables us to pinpoint any security vulnerabilities that can be exploited by attackers. 

For instance, from our previous example with the version scan, we were able to identify the version of Apache listening on port 80 (HTTP). A security-conscious individual can then search for any CVEs (Common Vulnerabilities and Exposures) or vulnerabilities associated with that specific version of Apache. This information empowers us to adopt security measures, like patching vulnerabilities, to mitigate potential risks. 

## Scan Techniques: 

Previously we described basic scan method, including a summary on version scan and how it can be used to identify any vulnerable services that need to be mitigated.  Here we will go deeper into different scan types and later into advanced scan technique.  

### TCP Connect Scan (-sT):  

TCP connect scan is `default TCP scan type when a user does not have enough privileges to utilize raw packets or scanning IPv6 networks`. In this approach, Nmap leverages the operating system's `connect` system call to establish a connection with the target machine's port. While this scan can be considered more reliable with port scan. However, as this scan completes three-way handshake, target machines are more likely to log the connection. Additionally, If we scan without targeting a specific port by default TCP connect scan will scan all the ports from `0 to 65535`, making it more time consuming.   

The below image shows a connect scan in action against open `port 22 (SSH) of scanme.nmap.org.`  
 
![img-description](/assets/img/posts/nmap/3.png) _Connect Scan, image credit: nmap.org_  

Here the client (Kard) initiates the connection by sending a SYN packet to the target system (scanme). The target system responds with a SYN/ACK packet, and then the client sends an ACK packet to establish the connection. During this process, the target system may send additional information, such as an SSH banner string `(e.g., "SSH-1.99-OpenSSH_3.1p1\n")`, providing insights into the service running on the open port. As soon as Nmap confirms the successful establishment of the connection through its host OS, it terminates the connection by sending FIN packet. 

Below a sample output of a connect scan.

```bash
┌──(kasyap㉿Brahma)-[~]
└─$ nmap -sT scanme.nmap.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-01 21:24 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
25/tcp    filtered smtp
80/tcp    open     http
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
9929/tcp  open     nping-echo
31337/tcp open     Elite

Nmap done: 1 IP address (1 host up) scanned in 14.28 seconds
```

The `-sT`option could have been omitted since Nmap is being run from a `non-privileged` account so connect scan is the default type.

### SYN Stealth Scan (-sS):   

SYN scan is the default and most popular Nmap scan option. However, to enable this scan the user typically needs standard user privileges (not necessarily root). While raw socket access can sometimes enhance performance, it is not essential for SYN scans. 

Compared to connect scans, SYN scans are faster because they do not complete the three-way handshake. On an unencumbered network (without firewalls or IDS), they can process ports quicker. Earning its nickname "stealth scan," a SYN scan avoids establishing a full connection, potentially making it less conspicuous. Additionally, it provides clear differentiation between open, closed, and filtered ports. 

![img-description](/assets/img/posts/nmap/4.png) _SYN Scan, image credit: nmap.org_

As shown in the example above, the first two steps (SYN and SYN/ACK) are the same as with a connect scan. However, instead of sending an ACK packet in response to the SYN/ACK sent by the target system (scanme), the client (Kard) responds with an RST packet, which terminates the connection attempt instead of establishing it. Ideally, if we do not send an RST packet to scanme, it will assume that there was a connection drop and keep sending SYN/ACK until it times out eventually. This way, the three-way handshake is never completed, hence SYN scan is sometimes called half-open scanning."

Below a sample output of a SYN scan.

```bash
┌──(root㉿Brahma)-[/home/kasyap]
└─# nmap -sS scanme.nmap.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-03 16:28 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 993 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
25/tcp    filtered smtp
80/tcp    open     http
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
9929/tcp  open     nping-echo
31337/tcp open     Elite

Nmap done: 1 IP address (1 host up) scanned in 5.26 seconds
```
### UDP Scan (-sU): 

Even though most internet services run on TCP, UDP also plays a vital role. Common examples include DNS (port 53), SNMP (ports 161/162), and DHCP (ports 67/68). While UDP scans are slower and trickier than TCP scans, some security professionals ignore UDP ports altogether. This is a mistake! Hackers target vulnerabilities in UDP services, and Nmap can help you identify those ports. 

To perform a UDP scan with Nmap, use the -sU option. You can even combine it with a TCP scan type (like SYN scan with -sS) to check both protocols at once. 

__Here's how UDP scanning works:__  

Nmap sends a UDP packet to each port you specify. Most packets are empty, but some well-known ports might receive a specific payload. Based on the response (or lack thereof), Nmap classifies the port into one of four states: 

- Open: If a UDP packet is received in response to the scan packet, it indicates an open port with a service potentially listening on it. 

- Closed: 
  If an ICMP Port Unreachable message (type 3, code 3) is received, it signifies a closed port. This response implies the port is not in use and is filtering incoming packets. 
  In some cases, the target device might not be configured to send ICMP messages for unreachable ports. The lack of any response (timeout) after a retransmission attempt might also suggest a closed port, but it is less conclusive than receiving an ICMP message. 

- Filtered: 
  If an ICMP message other than "Port Unreachable" (type 3, code 3) is received (e.g., ICMP message indicating a general network issue), it suggests a filter or security system might be blocking the scan packet, making it difficult to determine the actual port state (open or closed). 

- Open-Filtered:
  If no response is received after a retransmission attempt and there is no ICMP message to clarify, the port state is classified as "open|filtered." This indicates ambiguity; the port could be open and not responding (silent service), or it could be filtered by a security system. 

Below a sample output of a UDP scan.

```bash
root@Brahma:/home/kasyap# nmap -sU scanme.nmap.org
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-06 19:27 IST
Stats: 0:00:28 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 3.61% done; ETC: 19:41 (0:12:54 remaining)
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 991 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
123/udp open          ntp
135/udp open|filtered msrpc
136/udp open|filtered profile
137/udp open|filtered netbios-ns
138/udp open|filtered netbios-dgm
139/udp open|filtered netbios-ssn
162/udp open|filtered snmptrap
445/udp open|filtered microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1089.19 seconds
```

### TCP FIN, NULL, and Xmas Scans (-sF, -sN, -sX):
These are advanced TCP scan techniques used in Nmap with specific flags (-sF, -sN, -sX) to probe ports and potentially bypass basic filtering mechanisms. However, it's important to understand that they are less reliable than standard scans and may not always provide accurate results. Here is a breakdown of each: 

#### TCP FIN Scan (-sF) 

Nmap sends a TCP segment with only the FIN flag set. This flag typically indicates the end of a connection. Aiming to exploit firewalls or filters that might allow FIN packets to pass through while blocking standard connection attempts. 

By sending a FIN packet, the scanner hopes the target might respond with an RST (reset) packet, revealing information about the port state (open or closed). 
- __Limitations:__ 
   - Firewalls might not respond to unexpected FIN packets, making interpretation difficult. 
   - Only differentiates between open and closed ports, not filtered ones. 
   - Firewalls and IDS systems might recognize this as a scan attempt. 

#### TCP NULL Scan (-sN) 
Nmap sends a TCP segment with no flags set (empty header), trying to bypass firewalls that filter based on flags in the TCP header. A completely empty packet might be allowed through, and the target's response (RST or no response) could provide clues about the port state. 
- __Limitations:__ 
   - Target behaviour is unpredictable, making interpretation of responses challenging. 
   - Like FIN scan, it might only distinguish open/closed ports. 
   - Firewalls and IDS systems are likely to flag such unusual packets. 

#### Xmas Scan (-sX) 
Nmap sends a TCP segment with all flags set (FIN, SYN, PSH, URG, RST, ACK). This combination resembles a string of Christmas lights, hence the name. Like NULL scans, this aims to exploit firewalls that filter based on specific flag combinations. The scanner hopes for a response that might reveal the port state. 
- __Limitations:__ 
   -  Target behaviour is highly unpredictable, making response interpretation almost impossible. 
   - Provides extraordinarily little value in determining port states. 
   - Firewalls and IDS systems are likely to identify this as a suspicious scan attempt. 

Below sample for `FIN Scan` where, I have specifed the ports 25,135,139 using `-p` flag. The output for NULL and Xmas are the same as what we get in FIN.
   
```bash
root@Brahma:/home/kasyap# nmap -sF -p 25,135,139 scanme.nmap.org
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-06 20:49 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.25s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

PORT    STATE         SERVICE
25/tcp  open|filtered smtp
135/tcp open|filtered msrpc
139/tcp open|filtered netbios-ssn

Nmap done: 1 IP address (1 host up) scanned in 3.91 seconds
```
