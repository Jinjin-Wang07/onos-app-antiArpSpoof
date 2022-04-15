#!/usr/bin/python
#-*- coding:utf-8 -*-

import re
import sys
import time
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.util import quietRun
from mininet.node import OVSSwitch, OVSController, Controller, RemoteController
from mininet.topo import Topo


class MyTopo(Topo):  # "this topo is used for the Demo"
    def __init__(self):
        "Create custom topo."
        # Initialize topology
        Topo.__init__(self)
        
        # Add hosts
        h1 = self.addHost('h1', ip='0.0.0.0/24', defaultRoute="via 10.0.0.254")
        h2 = self.addHost('h2', ip='0.0.0.0/24', defaultRoute="via 10.0.0.254")
        h3 = self.addHost('h3', ip='0.0.0.0/24', defaultRoute="via 10.0.0.254")
        
        # Add switches
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Add links
        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s1, h3)


# Check if the interface is occupied
def checkIntf(intf):
    "Make sure intf exists and is not configured."
    if (' %s:' % intf) not in quietRun('ip link show'):
        error('Error:', intf, 'does not exist!\n')
        exit(1)
    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', quietRun('ifconfig ' + intf))
    if ips:
        error('Error:', intf, 'has an IP address, and is probably in use!\n')
        exit(1)


if __name__ == '__main__':
    setLogLevel('info')

    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[1] if len(sys.argv) > 1 else 'eth1'
    info('*** Connecting to hw intf: %s' % intfName)
    info('*** Checking', intfName, '\n')
    checkIntf(intfName)
    
    info('*** Creating network\n')
    
    # Key functions, create mininet network.
    net = Mininet(topo=MyTopo(), controller=None)

    # Get the switch and connect it to interface
    switch = net.switches[0]
    
    info('*** Adding hardware interface', intfName, 'to switch', switch.name, '\n')
    _intf = Intf(intfName, node=switch)  # Bridge the interface card with switch

    # Add the Onos controller
    c0 = RemoteController('c0', ip='172.17.0.2', port=6653)
    net.addController(c0)
    
    net.start()

    # Configure hosts ip using DHCP
    info('*** Dynamic Host Configuration : \n')
    for host in net.hosts:
        host.cmdPrint('dhclient '+host.defaultIntf().name)
        rtn = host.cmd('ifconfig ' + host.defaultIntf().name + '\n')
        ip = re.findall(r'\d+\.\d+\.\d+\.\d+', rtn)
        info('IP of ' + host.name + ' : ' + ip[0] + '\n')

    CLI(net)
    net.stop()
