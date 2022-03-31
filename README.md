# An SDN-based ARP spoofing detection application

- Due to the limitations of traditional network detection methods for ARP spoofing, our project has developed an ONOS application using SDN technology to detect ARP attacks.

- The controller first gets the Ip-Mac pairs. Then it monitors the network by controlling the forwarding rules of the switch. When illegal ARP packets are detected, it logs the information and issues rules to the switch to prohibit the attacker from accessing the network.

## Environment
- Onos 2.6.0
- Mininet 2.2.2
- Maven 3.6.3
- Arpspoof

## How to use it?
```
$ git clone https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof.git
$ cd onos-app-antiArpSpoof/
$ mvn clean install
$ onos-app localhost install target/onos-app-antiArpSpoof-1.0.0.oar
```

In Onos CLI 
```
onos> app activate antiArpSpoof
```
Then in the Onos terminal, you can see the start of the application.
![StartInfo](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/startInfo.png)

## Example
### 1. Run Onos and app-antiArpSpoof first

### 2. Create a simple topo with 3 hosts and a switch and connect to the controller.
```
$ sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovs,protocols=OpenFlow13 --topo single,3
```
### 3. In Mininet
```
mininet> pingall
```
![MininetPingAll](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/mininetPingAll.png)
The switch will submit all packets that there isn't a flow rule corresponding. After Received the packets, the controller will check its legality,  If the packet is a normal packet, it will forward a flow rule to switch which allow this flow pass through.

We can see the log info in the Onos terminal and check the flow rules : 
- information in Onos terminal:
![pingAllInfoTerm](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/pingInfoInOnosTerm.png)
- Flow Rules in the switch:
![flowsPing](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/flowsPing.png)

### 4. launch attack by h1
`arpspoof -i h1-eth0 -t 10.0.0.2 -r 10.0.0.3`

### 5. Result
- The Controller will detect the illegal packet and block all packet from h1
![warnInfo](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/warnInfo.png)
![bandFlow](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/blob/main/screenshots/bandFlow.png)

- h1 network blocked by switch: 
![AfterAttack](https://github.com/Jinjin-Wang07/onos-app-antiArpSpoof/raw/main/screenshots/AfterAttack.png#pic_center)

