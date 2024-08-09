# OSCP Commands

[Nmap](Nmap) </br>
[NetCat-NC](#NetCat-NC)

##### Nmap
Nmap Port Scan </br>
```
nmap -sC -sV --open -oN Nmap target
```
##### NetCat-NC
Scan the ports through netcat nc </br>
scan 1 to 1023 ports
```
nc -zv target 1-1023
```
