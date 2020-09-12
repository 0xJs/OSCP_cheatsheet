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
   1. Spiking: Find the vulnerable parameter
   2. Fuzzing: Get the amount of bytes the program crashes
   3. Find the offset: Get the amount of bytes to write to the EIP
   4. Overwriting the EIP
   5. Find bad characters: Run all hex characters through the program
   6. Finding the right module: Look for a ddl without memory protections
   7. Generating shellcode: To get a reverse shell or to run calc
   
#### Spiking: Find the vulnerable parameter
1. Take the commands/options/parameters one at a time and send a bunch of data to see if it crashes
2. Use `generic_send_tcp <HOST> <PORT> <SPIKE SCRIPT> 0 0` to send a spike script
   Spike script: see trunk/stats.spk for an example
#### Fuzzing: Get the amount of bytes the program crashes
1. Get the amount of bytes it crashes the program
   See template_fuzzing1.py for an example script.

#### Find the offset: Get the amount of bytes to write to the EIP
1.	Create a pattern with (pattern_create.rb from Metasploit). Use the -l parameter for the size.
```/usr/share/Metasploit-framework/tools/exploit/pattern_create.rb -l <length>```
```!mona pc <length>```
2.	Edit the script to send the offset.
   See template_fuzzing2.py 
3.	Send the offset and get the EIP value out of the debugger
4. Use the pattern_offset.rb to get the offset location
```/usr/share/Metasploit-framework/tools/exploit/pattern_offset.rb -l <length> -q <EIP VALUE>```
```!mona po <EIP VALUE>```


#### Overwriting the EIP

#### Find bad characters: Run all hex characters through the program

#### Finding the right module: Look for a ddl without memory protections

#### Generating shellcode: To get a reverse shell or to run calc

 
# Enumeration
 
# Exploitation
 
# Post Exploitation
 
## Local privilege escalation
### Windows

### Linux
 
## Lateral movement
