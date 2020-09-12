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
   
#### Spiking
1. Take the commands/options/parameters one at a time and send a bunch of data to see if it crashes
2. Use `generic_send_tcp <HOST> <PORT> <SPIKE SCRIPT> 0 0` to send a spike script
   Spike script: see trunk/stats.spk for an example
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
1.	Create a offset pattern.
```/usr/share/Metasploit-framework/tools/exploit/pattern_create.rb -l <length>```
```!mona pc <length>```
2.	Edit the script to send the offset pattern.
   See template_fuzzing2.py 
3.	Send the offset pattern and get the EIP value out of the debugger.
4. Get the offset location.
```/usr/share/Metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <EIP VALUE>```
```!mona po <EIP VALUE>```

#### Overwriting the EIP
1. Edit the script, comment out the offset and change the buffer to overwrite the buffer with 4 B's
   See template_fuzzing3.py

#### Find bad characters
1. Get a list of bad characters
https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/
https://github.com/cytopia/badchars
2. Edit the script, comment out the offset and change the buffer to send the bad characters
   See template_fuzzing4.py

#### Finding the right module

#### Generating shellcode

 
# Enumeration
 
# Exploitation
 
# Post Exploitation
 
## Local privilege escalation
### Windows

### Linux
 
## Lateral movement
