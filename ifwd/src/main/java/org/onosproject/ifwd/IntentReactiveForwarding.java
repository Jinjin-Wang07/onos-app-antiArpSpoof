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
package org.onosproject.ifwd;
//
//import org.osgi.service.component.annotations.Activate;
//import org.osgi.service.component.annotations.Component;
//import org.osgi.service.component.annotations.Deactivate;
// import org.osgi.service.component.annotations.Reference;
// import org.osgi.service.component.annotations.ReferenceCardinality;


//
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostAdminService;
import org.onosproject.net.host.HostDescription;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Arrays;
import java.util.EnumSet;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true)
public class IntentReactiveForwarding {
    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;


    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;

    private static final int DROP_RULE_TIMEOUT = 300;

    // protected HostAdminService hostAdminService;
    // 3 type of intent
    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                                                                            IntentState.WITHDRAWING,
                                                                            IntentState.WITHDRAW_REQ);

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.ifwd");
        packetService.addProcessor(processor, PacketProcessor.DIRECTOR_MAX);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("+++++++++++++++++++++++++++++++++++++++APP Start++++++++++++++++++++++++++++++++++++++");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        System.out.println("++++++++++++++++++++++++++++++++++++APP Deactivate++++++++++++++++++++++++++++++++++++");
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {
        private class MyARP{
            private final MacAddress srcMac;
            private final MacAddress dstMac;
            private final String packetSrcIp;
            private final String packetDstIp;

            MyARP(Ethernet ethPkt){
                String arpContenu = ethPkt.toString();
                int beginI = arpContenu.indexOf("nw_s");
                int endI = arpContenu.indexOf("nw_d");
                packetSrcIp = arpContenu.substring(beginI + 8, endI - 1);
                packetDstIp = arpContenu.substring(endI + 8);
                srcMac = ethPkt.getSourceMAC();
                dstMac = ethPkt.getDestinationMAC();
            }

            public MacAddress getSrcMac() {
                return srcMac;
            }

            public MacAddress getDstMac() {
                return dstMac;
            }

            public String getPacketSrcIp() {
                return packetSrcIp;
            }

            public String getPacketDstIp() {
                return packetDstIp;
            }

            @Override
            public String toString() {
                return  "-------> ARP Package INFO : " +
                        " SRC MAC : [" + srcMac.toStringNoColon() +
                        "], SRC IP  : [" + packetSrcIp +
                        "], DST MAC : [" + dstMac +
                        "], DST IP  : [" + packetDstIp + "]";
            }
        }

        @Override
        public void process(PacketContext context) {
            //if (context.isHandled()) {
                // return;
            //}
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            MyARP arpPacket = new MyARP(ethPkt);

            // Afficher les informations de ce packet
            System.out.println(arpPacket);

            // Obtenir les informations (qui sont stocke dans controlleur onos) de src et dst
            HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
            Host src = hostService.getHost(srcId);
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
            Host dst = hostService.getHost(dstId);

            for(IpAddress ipAddress: src.ipAddresses()){
                if(! arpPacket.getPacketSrcIp().equals(ipAddress.toString())){
                    log.error("Stored src ip of the sender : " + ipAddress);
                    log.error("Src IP in arp packet        : " + arpPacket.getPacketSrcIp());
                    log.error("There is a ARP Spoofing !!!!!!");
                    return;
                }
            }

            // Si c'est un package normal, controlleur le faire forward
            System.out.println("Every things goes will");
            setUpConnectivity(context, srcId, dstId);
            forwardPacketToDst(context, dst);
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(),
                                                          treatment, context.inPacket().unparsed());
        packetService.emit(packet);
        System.out.println("Packet Re-forward");
        // log.info("sending packet: {}", packet);
    }

    // Install a rule forwarding the packet to the specified port.
    private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
        try {
            TrafficSelector selector = DefaultTrafficSelector.emptySelector();
            TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

            Key key;
            if (srcId.toString().compareTo(dstId.toString()) < 0) {
                key = Key.of(srcId.toString() + dstId.toString(), appId);
            } else {
                key = Key.of(dstId.toString() + srcId.toString(), appId);
            }

            HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
            // TODO handle the FAILED state
            if (intent != null) {
                if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                    HostToHostIntent hostIntent = HostToHostIntent.builder()
                            .appId(appId)
                            .key(key)
                            .one(srcId)
                            .two(dstId)
                            .selector(selector)
                            .treatment(treatment)
                            .build();

                    intentService.submit(hostIntent);
                } else if (intentService.getIntentState(key) == IntentState.FAILED) {

                    TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                            .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                    TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                            .drop().build();

                    ForwardingObjective objective = DefaultForwardingObjective.builder()
                            .withSelector(objectiveSelector)
                            .withTreatment(dropTreatment)
                            .fromApp(appId)
                            .withPriority(intent.priority() - 1)
                            .makeTemporary(DROP_RULE_TIMEOUT)
                            .withFlag(ForwardingObjective.Flag.VERSATILE)
                            .add();

                    flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
                }

            } else if (intent == null) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            }
        } catch (Exception e){
            System.out.println(e.getMessage());
            // e.printStackTrace();
        }
    }



}
