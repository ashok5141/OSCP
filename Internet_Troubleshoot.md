### Parrot OS Internet not working tried these commands

````bash
ifconfig (Only see localhost 127.0.0.1)
ip a (if you see ens33 is down)
sudo ip link set ens33 up
ip a (it's up)
sudo systemctl restart NetworkManager
sudo systemctl restart networking

ip a
sudo dhclient ens33
 # It hangs
 sudo dhclient -r ens33
sudo dhclient ens33
ip a
sudo ip addr add 192.168.1.100/24 dev ens33
sudo ip route add default via 192.168.1.1
ping -c 4 8.8.8.8  (It worked)


# Other cases Not followd this
sudo apt update && sudo apt install firmware-realtek network-manager -y
sudo modprobe e1000
sudo reboot


```
