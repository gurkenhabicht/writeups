# Splunk Writeup
earching for values, it's fairly typical within security to look for uncommon events. What command can we include within our search to find these?

## Can you dig it?
Splunk queries always begin with this command implicitly unless otherwise specified. What command is this? When performing additional queries to refine received data this command must be added at the start. This is a prime example of a slight trick question.
```
search
```

When searching for values, it's fairly typical within security to look for uncommon events. What command can we include within our search to find these?
```
rare
```

What about the inverse? What if we want the most common security event?
```
top
```

When we import data into splunk, what is it stored under?
```
index
```

We can create 'views' that allow us to consistently pull up the same search over and over again; what are these called?
* dashboard

Importing data doesn't always go as planned and we can sometimes end up with multiple copies of the same data, what command do we include in our search to remove these copies?
```
dedup
```

Splunk can be used for more than just a SIEM and it's commonly used in marketing to track things such as how long a shopping trip on a website lasts from start to finish. What command can we include in our search to track how long these event pairs take?
```
transaction
```

In a manner similar to Linux, we can 'pipe' search results into further commands, what character do we use for this?
```
|
```

In performing data analytics with Splunk (ironically what the tool is at it's core) it's useful to track occurrences of events over time, what command do we include to plot this?
```
timechart
```

What about if we want to gather general statistical information about a search?
```
stats
```

Data imported into Splunk is categorized into columns called what?
```
fields
```

When we import data into Splunk we can view it's point of origination, what is this called? I'm looking for the machine aspect of this here.
```
host
```

When we import data into Splunk we can view its point of origination from within a system, what is this called?
```
source
```

We can classify these points of origination and group them all together, viewing them as their specific type. What is this called? Use the syntax found within the search query rather than the proper name for this.
```
sourcetype
```

When performing functions on data we are searching through we use a specific command prior to the evaluation itself, what is this command?
```
eval
```

Love it or hate it regular expression is a massive component to Splunk, what command do we use to specific regex within a search?
```
rex
```

It's fairly common to create subsets and specific views for less technical Splunk users, what are these called?
```
pivot table
```

What is the proper name of the time date field in Splunk
```
_time
```

How do I specifically include only the first few values found within my search?
```
head
```

More useful than you would otherwise imagine, how do I flip the order that results are returned in?
```
reverse
```

When viewing search results, it's often useful to rename fields using user-provided tables of values. What command do we include within a search to do this?
```
lookup
```

We can collect events into specific time frames to be used in further processing. What command do we include within a search to do just that?
```
bucket
```

We can also define data into specific sections of time to be used within chart commands, what command do we use to set these lengths of time? This is different from the previous question as we are no longer collecting for further processing.
```
span
```

When producing statistics regarding a search it's common to number the occurrences of an event, what command do we include to do this?
```
count
```

Last but not least, what is the website where you can find the Splunk apps at?
```
splunkbase.splunk.com
```

We can also add new features into Splunk, what are these called?
```
apps
```

What does SOC stand for?
```
Security Operation Center
```

What does SIEM stand for?
```
Security Information and Event Management
```

How about BOTS?
```
Boss of the SOC
```

And CIM?
```
Common Information Model
```

what is the website where you can find the Splunk forums at?
```
community.splunk.com
```

## BOTS
[Website](https://www.splunk.com/blog/2017/09/06/what-you-need-to-know-about-boss-of-the-soc.html)

## Halp, I'm drowning in logs!
Lockheed Martin's killchain
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Action on Objectives

## Advanced Persistent Threat
What IP is scanning our web server?
* `index=botsv1 imreallynotbatman.com sourcetype="stream:http" | top src_ip`
```
40.80.148.42
```

What web scanner scanned the server?
* `index=botsv1 imreallynotbatman.com src_ip=40.80.148.42 sourcetype=stream:http | stats count by http_user_agent`
```
Acunetix
```

What is the IP address of our web server?
* `index=botsv1 imreallynotbatman.com src_ip=40.80.148.42 sourcetype=stream:http 
| stats count by dest_ip`
```
192.168.250.70
```

What content management system is imreallynotbatman.com using?
* `index=botsv1 imreallynotbatman.com src_ip=40.80.148.42 sourcetype=stream:http dest=192.168.250.70 
|  stats count by uri 
|  sort - count`
```
joomla
```

What address is performing the brute-forcing attack against our website?
* `index=botsv1 sourcetype=stream:http dest=192.168.250.70 form_data=*username*passwd*
| stats count by http_method, src_ip`
```
23.22.63.114
```

What was the first password attempted in the attack?
* `index=botsv1 sourcetype=stream:http dest=192.168.250.70 src=23.22.63.114 form_data=*username*passwd*
| table form_data 
| sort _time 
| reverse`
```
12345678
```

One of the passwords in the brute force attack is James Brodsky's favorite Coldplay song. Which six character song is it?
* `index=botsv1 sourcetype=stream:http form_data=*username*passwd* 
| rex field=form_data "passwd=(?<userpassword>\w+)" 
| eval lenpword=len(userpassword) 
| search lenpword=6 
| eval password=lower(userpassword) 
| lookup coldplay.csv song as password OUTPUTNEW song
| search song=*
| table song password`
```
yellow
```

What was the correct password for admin access to the content management system running imreallynotbatman.com?
* `index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 | rex field=form_data "passwd=(?<userpassword>\w+)" 
| stats count by userpassword
| sort - count`
```
batman
```

What was the average password length used in the password brute forcing attempt rounded to closest whole integer?
* `index=botsv1 sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 | rex field=form_data "passwd=(?<userpassword>\w+)"
| eval plen=len(userpassword) 
| stats avg(plen) as alen
| eval alen=round(alen,0)
`
```
6
```

How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login rounded to 2 decimal places?
* `index=botsv1 sourcetype=stream:http
| rex field=form_data "passwd=(?<userpassword>\w+)" 
| search userpassword=batman 
| transaction userpassword 
| table duration`
```
92.17
```

How many unique passwords were attempted in the brute force attempt?
* `index=botsv1 sourcetype=stream:http form_data=*username*passwd*  | rex field=form_data "passwd=(?<userpassword>\w+)" | stats dc(userpassword)`
```
412
```

What is the name of the executable uploaded by P01s0n1vy?
* `index=botsv1 sourcetype=suricata dest_ip="192.168.250.70" http.http_method=POST .exe 
| table filename`
```
3791.exe
```

What is the MD5 hash of the executable uploaded?
* `index=botsv1 3791.exe CommandLine=3791.exe 
| stats values(MD5)`
```
AAE3F5A29935E6ABCC2C2754D12A9AF0
```

What is the name of the file that defaced the imreallynotbatman.com website?
* `index=botsv1 sourcetype=fgt_utm "192.168.250.70" NOT dest="192.168.250.70"| top limit=5 url`
```
poisonivy-is-coming-for-you-batman.jpeg
```

This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?
* `index=botsv1 sourcetype=fgt_utm "poisonivy-is-coming-for-you-batman.jpeg" 
| stats count by hostname`
```
prankglassinebracket.jumpingcrab.com
```

What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?
* `index=botsv1 sourcetype=fgt_utm "poisonivy-is-coming-for-you-batman.jpeg" 
| table hostname, dstip`
```
23.22.63.114
```

Based on the data gathered from this attack and common open source intelligence sources for domain names, what is the email address that is most likely associated with P01s0n1vy APT group?
* The registrant email has changed by now. I had to cheese this one.
```
lillian.rose@po1s0n1vy.com
```

GCPD reported that common TTPs (Tactics, Techniques, Procedures) for the P01s0n1vy APT group if initial compromise fails is to send a spear phishing email with custom malware attached to their intended target. This malware is usually connected to P01s0n1vy’s initial attack infrastructure. Using research techniques, provide the SHA256 hash of this malware.
* Querying on [threadminer.org](https://www.threatminer.org/host.php?q=23.22.63.114) for the IP will return three MD5 checksums. Pasting the first one into virustotal search engine yields `3971.exe` as an answer. The second one cannot be found by virustotal. This leaves us with the last one, [which is the correct answer](https://www.virustotal.com/en/file/9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8/analysis/).
```
9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8
```

What special hex code is associated with the customized malware discussed in the previous question?
* While still on the virustotal page, take a look inside the comments.
```
53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21
```

What does this hex code decode to?
```sh
echo "53 74 65 76 65 20 42 72 61 6e 74 27 73 20 42 65 61 72 64 20 69 73 20 61 20 70 6f 77 65 72 66 75 6c 20 74 68 69 6e 67 2e 20 46 69 6e 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 61 6e 64 20 61 73 6b 20 68 69 6d 20 74 6f 20 62 75 79 20 79 6f 75 20 61 20 62 65 65 72 21 21 21" | xxd -r -p
```
    ```
    Steve Brant's Beard is a powerful thing. Find this message and ask him to buy you a beer!!!
    ```

## Ransomware
What was the most likely IP address of we8105desk on 24AUG2016?
* Query
```
index=botsv1 we8105desk source=stream:smb 
| stats count by dest_ip
```
* Answer
```
192.168.250.100
```

What is the name of the USB key inserted by Bob Smith?
* Query
```
index=botsv1 sourcetype=winregistry friendlyname 
| table host object data
```
* Answer
```
MIRANDA_PRI
```

fter the USB insertion, a file execution occurs that is the initial Cerber infection. This file execution creates two additional processes. What is the name of the file?
* Query
```
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk (CommandLine="*d:\\*" OR ParentCommandLine="*d:\\*") 
| table _time CommandLine ParentCommandLine 
| sort _time
```
* Answer
```
Miranda_Tate_unveiled.dotm
```

During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length in characters of this field?
* Query 
```
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational *.exe CommandLine=* host=we8105desk EventCode=1 
| eval length=len(CommandLine) 
| table CommandLine length 
| sort - length
```
* Answer
```
4490
```

Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IP address of the file server?
* Query
```
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 192.168.250.20 host=we9041srv 
| table SourceIp
```
* Answer
```
192.168.250.20
```

What was the first suspicious domain visited by we8105desk on 24AUG2016?
* Query
```
index=botsv1  source=stream:dns date_mday=24 date_month="august" src=192.168.250.100 record_type=A 
| table query _time
| sort _time
```
* Answer
```
solidaritedeproximite.org
```
The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?
* Query
```
index=botsv1  source=stream:http date_mday=24 date_month="august" src=192.168.250.100 url=* 
| stats count values(url) by dest
```
* Answer
```
mhtr.jpg
```

What is the parent process ID of 121214.tmp?
* Query
```
Index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational 121214.tmp CommandLine=* | table CommandLine ProcessId ParentProcessId ParentCommandLine |reverse
```
* Answer
```
3968
```

Amongst the Suricata signatures that detected the Cerber malware, which signature ID alerted the fewest number of times?
* Answer
```
2816763
```


The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?
* Query
```
index=botsv1 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational host=we8105desk EventCode=2 TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt" 
| stats dc(TargetFilename)
```
* Answer
```
406
```

How many distinct PDFs did the ransomware encrypt on the remote file server?
* Query
```
index=botsv1 sourcetype=*win* pdf dest=we9041srv.waynecorpinc.local Source_Address=192.168.250.100 | stats dc(Relative_Target_Name)
```
* Answer
```
257
```

What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?
* Query
```
index=botsv1 sourcetype=stream:DNS src=192.168.250.100 record_type=A NOT (query{}=*.microsoft.com OR query{}=*.waynecorpinc.local OR query{}=*.bing.com OR query{}=isatap OR query{}=wpad OR query{}=*.windows.com OR query{}=*.msftncsi.com) | table _time query{} src dest
```
* Answer
```
cerberhhyed5frqa.xmfir0.win
```
