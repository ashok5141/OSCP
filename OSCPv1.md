# OSCP Commands
- Some revised commands
- 
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

## Linux

## Windows

## Active Directory

##### Users Active Directory
- If you don't know users in the active directory
- It allows the guest/anonymous shares
```bash
impacket-lookupsid 'domain/guest'@domain -no-pass
nxc smb IP -u 'anonymous' -p '' --rid-brute
```
