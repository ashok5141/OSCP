##Resources </br >
https://www.youtube.com/watch?v=DM1B8S80EvQ&t=1s  </br >
https://www.hdysec.com/double-pivoting-both-metasploit-and-manual/ </br >
https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5 </br >
```
>sudo ip tuntap add user kali mode tun ligolo
````

```
>./Lproxy -selfcert (Mention Port below)
```
WIN_PS>.\Lagent -connect 192.168.45.204:11601 -ignore-cert
Ligilo>ifconfig (Network interfaces)
>sudo ip route add 172.16.201.0/24 dev ligolo (Run this if you for got run above "sudo ip link set dev ligolo up")
Ligilo>start
>ping 172.16.201.11 (You should able to reach before executing next command)
