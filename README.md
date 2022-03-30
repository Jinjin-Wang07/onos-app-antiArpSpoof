# A SDN-based ARP spoofing detection application

- Due to the limitations of traditional network detection methods for ARP spoofing, our project has developed an ONOS application using SDN technology to detect ARP attacks.

- The controller first gets the Ip-Mac pairs. Then it monitors the network by controlling the forwarding rules of the switch. When illegal ARP packets are detected, it logs the information and issues rules to the switch to prohibit the attacker from accessing the network.

## Environment
- Onos 2.6.0
- Mininet 2.2.2
- Maven 3.6.3

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
