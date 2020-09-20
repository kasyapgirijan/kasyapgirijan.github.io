---
layout: post
title:  "Vulnhub: The Planets: Mercury"
date:  2020-09-20 15:00:.06 +0530
categories: Vulnhub_CTF
tags: Writeup Walkthrough
---
Hello All, We will see the walkthrough of vulnhub CTF machine The Planets: Mercury.

About the Machine: Mercury is an easier box, with no bruteforcing required. There are two flags on the box: a user and root flag which include an md5 hash.

Let's begin!

__Network Scanning:__

To identify the services running lets run nmap scan with command __*“nmap -sC -SV 192.168.0.197”*__  .
![nmap](/images/Mercury_1.png)

Well with having port 8080 enabled lets enumerate!!

I wasn't able to get anything interesting here, but out of luck to say I miss typed robots.txt and landed to "Page Not Found" which exposed __*"mercuryfacts/"*__ path.
![pagenotfound](/images/Mercury_2.png)

While browsing the path, I could observe __*Fact id: 1. (('Mercury does not have any moons or rings.',),)*__ under the link.

![SQLi](/images/Mercury_3.png)

Possible SQL injection here, provided I started off with sqlmap

![SQLMap_DB](/images/Mercury_4.png)

Got the database name  with the command __*sqlmap -u http://192.168.0.197:8080/mercuryfacts/ - -dbs*__  now lets enumerate for tables.

command : __sqlmap -u http://192.168.0.197:8080/mercuryfacts/ -D mercury - -tables - -batch__

![SQLMap_TB](/images/Mercury_5.png)

Now Lets dump password from users tables with command __*"sqlmap -u http://192.168.0.197:8080/mercuryfacts/ -D mercury -T users - -dump - -batch "*__

![SQLMap_PSD](/images/Mercury_6.png)

With few attempts I was able to login with SSH using the user __*"webmaster"*__ and password  __*"mercuryisthesizeof0.056Earths"*__.

![SQLMap_PSD](/images/Mercury_7.png)

__Privilege Escalation:__

Enumerating the home directory I observed mercury_proj folder which had two accounts details mentioned in *"notes.txt"*.

Further decoded the base64 encrypted password for linuxmaster!!

![PE_Linuxmaster](/images/Mercury_8.png)

Post logging in as Linuxmaster as usual I ran __*"sudo -l"*__ command.

![PE_Linuxmaster](/images/Mercury_9.png)

We can run check_syslog file as root !!! with some google-fu I learned that SETENV is used to set the environment variable's value.

Reading the check_syslog.sh file I could understand it basically runs __*"tail"*__ command on *syslog*

![PE_syslog.sh](/images/Mercury_10.png)

Maybe if we can manipulate to vim to run instead of tail we can do !bash to get root access.

After few google-fu I learned that with *"ln -s"* command we can create a symbolic link between tail and vim.

__*Command : "ln -s /var/bin/vim tail"*__.

__*Command to check if it was successful :"ls -la tail"*__.

![PE_syslog.sh](/images/Mercury_11.png)

To make this exploit working we need to change the PATH and would need to send all the variables to sudo by using --preserve-env command.

![PE_syslog.sh](/images/Mercury_12.png)

While running "__*sudo --preserve-env=PATH /usr/bin/check_syslog.sh*__" it will open up __*vim*__ where I entered "__:!bash__" giving out root shell.

This concludes the Writeup, Thank you !!!
