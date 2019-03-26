package com.javahelps.pcapparser;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {



    public static void main(String[] args) throws IOException {

        final Pcap pcap = Pcap.openStream("lbl-internal.20041004-1305.port002.dump.pcap");
        //final Map<, List> SYN = new HashMap<>();

        pcap.loop(new PacketHandler() {
            @Override
            public boolean nextPacket(Packet packet) throws IOException {
                //List<Packet> SYN = new ArrayList<>();
                //List<Packet> SYNACK = new ArrayList<>();
                Map<Packet, List> SYN = new HashMap<>();
                Map<Packet, List> SYNACK = new HashMap<>();
                if (packet.hasProtocol(Protocol.TCP)) {
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    if (tcpPacket.isSYN() && !tcpPacket.isACK()){
                        List<String> IPs = new ArrayList<>();
                        IPs.add(tcpPacket.getDestinationIP());
                        IPs.add(tcpPacket.getSourceIP());
                        SYN.put(tcpPacket, IPs);
                    }
                    if (tcpPacket.isACK() && tcpPacket.isSYN()){
                        List<String> IPs = new ArrayList<>();
                        IPs.add(tcpPacket.getDestinationIP());
                        IPs.add(tcpPacket.getSourceIP());
                        SYNACK.put(tcpPacket, IPs);
                    }

                    for (Map.Entry<Packet,List> entry : SYN.entrySet())
                        System.out.print("Key = " + entry.getKey().getName() +
                                " Value = " + entry.getValue());

                } else if (packet.hasProtocol(Protocol.UDP)) {
                    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
                }
                return true;
            }

        });
    }

}
