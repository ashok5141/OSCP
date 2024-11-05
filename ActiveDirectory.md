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








## Post-Compromise Enumeration


## Post-Compromise Attacks


## After Compromising Domain -What we can do



## Additional Active Directory Attacks 


## Active Directory Case Studies

