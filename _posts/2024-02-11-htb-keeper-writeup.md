---
title: Hack The Box | Keeper Writeup  
date: 2024-02-10 00:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [keeper.htb, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/keeper.webp
  lqip: data:image/png;base64,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
  
---
The Machine IP address (victim): 10.129.27.235

## Enumeration:

### Port Scan

``` bash
# Nmap 7.80 scan initiated Tue Jan 30 20:01:25 2024 as: nmap -sV -A -T5 -Pn -oA 10.129.27.235 10.129.27.235
Nmap scan report for tickets.keeper.htb (10.129.27.235)
Host is up (0.24s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login
|_http-trane-info: Problem with XML parsing of /evox/about
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   237.57 ms 10.10.14.1
2   237.73 ms tickets.keeper.htb (10.129.27.235)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
# Nmap done at Tue Jan 30 20:01:48 2024 -- 1 IP address (1 host up) scanned in 22.75 seconds
```

So, we have a SSH on default 22 and HTTP on port 80. I went ahead and browsed by pasting the IP address which gave out the host entry that I need to do to access the web application.

## Foothold:

![img-description](/assets/img/htb/keeper/1.png) _Host entry_

I went ahead and added tickets.keeper.htb to /etc/hosts and went back to web application which gave me a login screen for `Best practical RT`.

![img-description](/assets/img/htb/keeper/2.png) _Login prompt_

With my initial Google search, I came to know the default credential for the admin portal is root: password which worked! 

![img-description](/assets/img/htb/keeper/3.png) _Google FU: default RT password_

Post login I the first thing that came to my eyes was admin options which enables me to see user attributes. 

![img-description](/assets/img/htb/keeper/4.png) _Exploring Admin Options_

## Privilege Escalation:

### To User Access:

While exploring the user attributes, we can see in comment section the temporary password set for the user.

![img-description](/assets/img/htb/keeper/5.png) _Exploring Admin Options_

Using the credentials we obtained, I was able to gain access to the machine with through SSH.

![img-description](/assets/img/htb/keeper/6.png) _SSHL Login - User Owned_

We now own the USER for this machine!

### From User to Root:

As we see in above screenshot, we do have a ZIP file placed under the user’s folder. I downloaded the file and extracted the contents. 

The ZIP file had `passcodes.kdbx` and `KeePassDumpFull.dmp` by searching the web I these file belong to KeepPass password manager found a relevant  [PoC](https://github.com/vdohney/keepass-password-dumper) to retrieve master password from crash dump files.

![img-description](/assets/img/htb/keeper/7.png)_Google-Fu: KeePassDumpFull.dmp_

Okay next step is to boot a windows machine to use the PoC as it requires dotnet to run the exploit (effortless way). However, I to a chance and explored Linux version of dotnet and installed dotnet `SDK 7`, the required version for this PoC to work.

After setting up dotnet I went ahead and executed the exploit using the below.

```bash
dotnet run KeePassDumpFull.dmp
```
![img-description](/assets/img/htb/keeper/8.png)_executing PoC_

The exploit worked and gave out the below output to be “master password.”

![img-description](/assets/img/htb/keeper/9.png)_Output from Exploit_

While it made me think for a while, I went ahead and googled and could get the below result.
![img-description](/assets/img/htb/keeper/10.png)_Google FU: Master Password_

Which turns out to be `rødgrød med fløde` a Danish dessert and we do know Lnorgaard is from Denmark so, I tried it. 

For which I had to download [KeePass2] (https://keepass.info/) and opened `passcodes.kdbx` file which we extracted from the ZIP file and it worked.
> I initially tried `wine` but did not work for me so I used a `Windows 10 VirtualBox machine` for later steps. Also there is an alternative community based Linux version of keeppass2 avaliable. 
{: .prompt-warning }
![img-description](/assets/img/htb/keeper/11.png)_KeePass: Master Password_

Once we enter the “master password,” we see that root user have stored its SSH public key in `puttygen format`.
![img-description](/assets/img/htb/keeper/12.png)_KeePass: Root PuttyGen_
>Puttygen is a key generator tool that comes as part of the PuTTY suite, a popular open-source program for secure remote connections. Primarily, it focuses on generating and managing SSH keys, which are cryptographic pairs used for secure authentication on remote servers.
{: .prompt-info }

Now, what we need to do is to have the puttygen key saved into a ppk file and convert it into a pem file which might grant us ability to SSH as root.

>PPK: is puttygen file format `Putty Private Key`.
{: .prompt-info } 
>PEM: `private key format defined in [RFC1422](https://www.rfc-editor.org/rfc/rfc1422)` used by open source tools like `OpenSSL/OpenSSH`.
{: .prompt-info }

if you are using Linux machine for this step you might need to install putty-tools

```bash
sudor apt-get install putty-tools
```

Once installed you can convert/generate the private key from Putty Private key to pem by below command.

```bash
puttygen id_dsa.ppk -O private-openssh -o id_dsa
```

Now, as we have a private key that we can work with to login to SSH let us try it!
![img-description](/assets/img/htb/keeper/13.png)_Machine Owned!_

Done, the Key worked and we have the machine `ROOTED!`.
