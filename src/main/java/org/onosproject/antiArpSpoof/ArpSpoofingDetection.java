/*
 * Copyright 2014 Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.antiArpSpoof;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostAdminService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Set;

import static org.onosproject.net.flowobjective.Objective.MAX_PRIORITY;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true)
public class ArpSpoofingDetection {
    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

//    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
//    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

//    private static final int DROP_RULE_TIMEOUT = 300;

//    protected HostAdminService hostAdminService;
//     3 type of intent
//    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
//                                                                            IntentState.WITHDRAWING,
//                                                                            IntentState.WITHDRAW_REQ);

    public ReactivePacketProcessor processor;
    public ApplicationId appId;
    HashMap<IpAddress, MacAddress> ipMacPaire;

    /** Configure Flow Priority for installed flow rules; default is 10. */
    private int flowPriority = 10;

    /** Configure Flow Timeout for installed flow rules; default is 10 sec. */
    private int flowTimeout = 10;

    // DHCP configuration
    private final int DHCP_CLIENT_PORT = 68;
    private final int DHCP_SERVER_PORT = 67;
    private final IpAddress DHCP_SERVER_IP = IpAddress.valueOf("10.0.0.253");
    private final IpAddress GateWay = IpAddress.valueOf("10.0.0.254");

    @Activate
    public void activate() {
        ipMacPaire = new HashMap<>();
        appId = coreService.registerApplication("org.onosproject.antiArpSpoof");

        processor = new ReactivePacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info("+++++++++++++++++++++++++++++++++++++++APP Start++++++++++++++++++++++++++++++++++++++");
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info("++++++++++++++++++++++++++++++++++++APP Deactivate++++++++++++++++++++++++++++++++++++");
        log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    private void getIPMacPaire(HashMap<IpAddress, MacAddress> ipMacPaire){
        Iterable<Host> hosts = hostService.getHosts();
        for(Host h : hosts){
            Set<IpAddress> ips = h.ipAddresses();
            MacAddress macAddress = h.mac();
            for(IpAddress ip : ips){
                if(ipMacPaire.containsKey(ip)){
                    continue;
                }
                ipMacPaire.put(ip, macAddress);
            }
        }
    }

    /* To drop packet */
    private void createBandFlowRule(MacAddress illegalMac){
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthSrc(illegalMac);

        TrafficTreatment.Builder trafficBuilder = DefaultTrafficTreatment.builder();
        trafficBuilder.drop();
        FlowRule rule = DefaultFlowRule.builder()
                .forDevice(deviceService.getDevices().iterator().next().id())
                .withSelector(selector.build())
                .withTreatment(trafficBuilder.build())
                .fromApp(appId)
                .makePermanent()
                .withPriority(MAX_PRIORITY)
                .build();
        flowRuleService.applyFlowRules(rule);
        log.info("BAN Rule Applied !\n");
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    public class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                 return;
            }

            log.info("========== Start processing packets ===========");

            // getIPMacPaire(ipMacPaire);

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if(ethPkt == null){
                log.error("Packet Null ERROR");
                return;
            }

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                return;
            }

            if(ethPkt.getEtherType() == Ethernet.TYPE_ARP){
                ARP arpPayload = (ARP)(ethPkt.getPayload());
                if(arpPayload.getSenderProtocolAddress() == null){
                    log.warn("No IP src in Arp Packet");
                }

                IpAddress payloadSrcIp = IpAddress.valueOf(IpAddress.Version.INET, arpPayload.getSenderProtocolAddress());
                if (ipMacPaire.containsKey(payloadSrcIp)){
                    MacAddress ethSrcSha = ethPkt.getSourceMAC();
                    // When the information in the payload is not True, Band the Host with ethSrcSha
                    if(isArpSpoof(ethSrcSha, payloadSrcIp)) {
                        log.warn("Packet Illegal !!! ");
                        log.warn("============================================================================");
                        log.warn("Stocket IP-Mac Paire === " + payloadSrcIp + ":" + ipMacPaire.get(payloadSrcIp));
                        log.warn("Packet IP-MAC Paire  === " + payloadSrcIp + ":" + ethSrcSha);
                        log.warn("============================================================================");
                        createBandFlowRule(ethSrcSha);
                        return;
                    } else {
                        log.info("Normal ARP Packet");
                    }
                } else if(payloadSrcIp.isZero()){
                    log.info("ARP packet, Testing if ip is occupied");
                } else if(payloadSrcIp.isSelfAssigned()){
                    log.info("Arp announcement for a self Assigned Ip : 169.254.X.X");
                } else if(DHCP_SERVER_IP.getIp4Address().equals(payloadSrcIp.getIp4Address())){
                    log.info("DHCP server Arp");
                } else if(GateWay.getIp4Address().equals(payloadSrcIp.getIp4Address())){
                    log.info("Gateway Arp");
                } else {
                    log.warn("IP unknown : " + payloadSrcIp);
                    return;
                }
            }

            // Get the information of dst (stocker by onos)
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
            Host dst = hostService.getHost(dstId);

            // The packet is normal, install the forward rule and forward it.
            if(dst != null){
                log.info("Normal Packet, set flow rule");
                installRule(context, dst.location().port());
            } else {
                log.info("Got ARP BoardCast Packet");
                flood(context);
            }
            System.out.println();
        }
    }

    private boolean isArpSpoof(MacAddress ethSrcSha, IpAddress payloadSrcIp) {
        return !ethSrcSha.equals(ipMacPaire.get(payloadSrcIp));
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                context.inPacket().receivedFrom())) {
            log.info("Flood gotten packet");
            packetOut(context, PortNumber.FLOOD);
        } else {
            log.warn("Can't flood packet, no permission");
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
        log.info("Packet Sent");
    }

    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber) {
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        //    Create flows with default matching and include configured fields
        selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                .matchEthSrc(inPkt.getSourceMAC())
                .matchEthDst(inPkt.getDestinationMAC());

        // If configured and EtherType is IPv4 - Match IPv4 and
        // TCP/UDP/ICMP fields
        EthType ethType = new EthType(inPkt.getEtherType());
        log.info("Got Packet type == " + ethType);

        // The packet type detected is IPV4
        if (inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            // log.info("Is IPV4 Packet");
            IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
            byte ipv4Protocol = ipv4Packet.getProtocol();

            Ip4Prefix matchIp4SrcPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                            Ip4Prefix.MAX_MASK_LENGTH);

            Ip4Prefix matchIp4DstPrefix =
                    Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                            Ip4Prefix.MAX_MASK_LENGTH);

            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPSrc(matchIp4SrcPrefix)
                    .matchIPDst(matchIp4DstPrefix);

            if (ipv4Protocol == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                        .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                log.info("Set TCP Flow Rule");
            }


            // dhcp is at application layer, it uses UDP and the port: Client(68) Server(67)
            // Warning : Necessary a authentidicated DHCP server, to avoid the forge of dhcp packets.
            //
            if (ipv4Protocol == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                int srcPort = udpPacket.getSourcePort();
                int dstPort = udpPacket.getDestinationPort();

                /*
                    DHCP :
                    1：DHCP Discover
                    2：DHCP Offer
                    3：DHCP Request
                    4：DHCP ACK

                    Here we don't consider dhcp spoofing, just extract the info from DHCP_ACK
                 */
                if(srcPort == DHCP_CLIENT_PORT && dstPort == DHCP_SERVER_PORT) {
                    // A DHCP C to S : DHCP Discover / DHCP Request
                } else if (srcPort == DHCP_SERVER_PORT && dstPort == DHCP_CLIENT_PORT){
                    // A DHCP S to C : DHCP Offer / DHCP ACK
                    IpAddress srcIp = IpAddress.valueOf(ipv4Packet.getSourceAddress());
                    if(srcIp.equals(DHCP_SERVER_IP)){
                        extractDHCPInfo(udpPacket);
                    }
                }

                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                        .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                log.info("Set UDP Flow Rule");
            }

            if (ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                selectorBuilder.matchIPProtocol(ipv4Protocol)
                        .matchIcmpType(icmpPacket.getIcmpType())
                        .matchIcmpCode(icmpPacket.getIcmpCode());
                log.info("Set ICMP Flow Rule");
            }
        }

        TrafficTreatment treatment;
        treatment = DefaultTrafficTreatment.builder()
                .setOutput(portNumber)
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

        flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                forwardingObjective);
        log.info("Forward Flow Installed");

        //  Send packet direction on the appropriate port
        packetOut(context, portNumber);
    }


    /*
        Get the IP - MAC pair from DHCP packets
     */
    private void extractDHCPInfo(UDP udpPacket) {
        log.info("================= A DHCP ACK Packet ================");

        DHCP dhcpPacket = (DHCP) udpPacket.getPayload();
        IpAddress clientIp = IpAddress.valueOf(dhcpPacket.getClientIPAddress()); // 0.0.0.0 for the first time
        IpAddress yourIp = IpAddress.valueOf(dhcpPacket.getYourIPAddress());
        byte[] clientMacAddr = dhcpPacket.getClientHardwareAddress();
        MacAddress macAddress = MacAddress.valueOf(clientMacAddr);
        log.info("Client original Ip == " + clientIp);
        log.info("Client get Ip == " + yourIp);
        log.info("Client Mac Address == " + macAddress);
        log.info("Add Client Ip and Client Mac to Cache");

        // Refresh ip mac info
        ipMacPaire.remove(yourIp);
        ipMacPaire.put(yourIp, macAddress);
        log.info("====================================================");
        log.info("IP-MAC Cache === " + ipMacPaire.toString());
        log.info("====================================================");
    }
}
