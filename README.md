# An SDN-based ARP spoofing detection application
<p align="center">
  <img  width="310px" height="267px" src="https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/ProjectToPo.svg">
</p>

---
- ARP spoofing attack is mainly seen in LAN networks, which has no efficient solution to mitigate in traditional networks, our project developed an ONOS application to mitigate ARP spoofing attacks in Software-Defined Networks. The SDN approach does not require modification of the original ARP protocol. And because of its  centralized character, it can be applied to all users in the network.
- The defense method is mainly divided into two parts. In the first part, the controller inspects DHCP Reply messages to obtain the Client IP and Mac Address. Then it stores this IP-Mac pair in memory. For the second part, it monitors all ARP packets. If the IP address or the MAC address contained in any ARP packet is not the same as the recorded value, the packet will be dropped. And it sends rules to the switch to prohibit the attacker from accessing the network.
- We have tested different attack scenarios for its reliability, the tests are emulated by Mininet.
- The results show that our application can prevent both request and reply based ARP attacks.

## Environment
### Requirements
- Docker 20.10.14
- Mininet 2.2.2
- Arpspoof

### Set up
- Get the onos image
```
$ docker pull onosproject/onos:2.6-latest
```
- Setup the ONOS developers tools
```
$ git clone https://gerrit.onosproject.org/onos
$ cd onos
$ cat << EOF >> ~/.bash_profile
export ONOS_ROOT="`pwd`"
source ${ONOS_ROOT}/tools/dev/bash_profile
EOF
$ . ~/.bash_profile
```

## Install and run the app
- Run first the onos container
``` 
$ sudo docker run -t -d -p 8181:8181 -p 8101:8101 -p 5005:5005 -p 830:830 --name onos onosproject/onos:2.6-latest 
$ sudo docker logs -f onos # Display onos output information
```
- Activate necessary apps
```
$ onos-app -u karaf -p karaf 172.17.0.2 activate org.onosproject.openflow
```
- Download the Anti-Spoof Application
```
$ git clone https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof.git
$ cd onos-app-antiArpSpoof/
$ onos-app -u karaf -p karaf 172.17.0.2 install ./target/onos-app-antiArpSpoof-1.0.0.oar
$ onos-app -u karaf -p karaf 172.17.0.2 activate org.onosproject.antiArpSpoof
```

Then in the Onos output, you can see the start of the application.
![StartInfo](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/startInfo.png)


## Demo
### 1. Run Onos and app-antiArpSpoof first
### 2. Configure the DHCP interface
The experiment is carried out in a virtual machine. 
Assign a bridge/host-only mode interface to the virtual machine, and clear its IP.
Should note that 
### 2. Start the mininet with the topo.py
```
$ sudo python2 topo.py interface_name
```
<p>
  <img  width="310px" height="267px" src="https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/ProjectToPo.svg">
</p>

This script builds a simple network, the network topology is shown in the figure, when the network is built, the hosts uses DHCP to request an ip address.
When the Onos controller monitors the DHCP traffic, it saves the Client Ip-Mac pair in the DHCP ACK packet.

![mininetStart](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/mininetStart.png#pic_center)

![getDhcpPacket](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/getDhcpPacket.png)

### 3. Test network connectivity
The switch will submit all packets that there isn't a flow rule corresponding. After Received the packets, the controller will check its legality,  If the packet is a normal packet, it will forward a flow rule to switch which allow this flow pass through.

We can see the log info in the Onos output and check the flow rules : 
- information in Onos terminal:
![pingAllInfoTerm](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/pingInfoInOnosTerm.png)
- Flow Rules in the switch:
![flowsPing](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/flowsPing.png)

### 4. launch attack by h1
```
arpspoof -i h1-eth0 -t 10.0.0.246 -r 10.0.0.247
```
### 5. Result
- The Controller will detect the illegal packet and block all packet from h1
![warnInfo](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/warnInfo.png)
![bandFlow](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/bandFlow.png)

- h1 network blocked by switch: 

- ![AfterAttack](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/raw/main/screenshots/AfterAttack.png#pic_center)
