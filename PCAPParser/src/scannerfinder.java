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

public class scannerfinder {

    public static void main(String[] args) throws IOException {
        final long startTime = System.nanoTime();
        //final Pcap pcap = Pcap.openStream("lbl-internal.20041004-1305.port002.dump.pcap");
        final Pcap pcap = Pcap.openStream(args[0]);
        final Map<String, Integer> SYN_count = new HashMap<>();
        final Map<String, Integer> SYNACK_count = new HashMap<>();

        pcap.loop(new PacketHandler() {
            @Override
            public boolean nextPacket(Packet packet) throws IOException {
                if (packet.hasProtocol(Protocol.TCP)) {
                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    if (tcpPacket.isSYN() && !tcpPacket.isACK()) { // SYN
                        if (SYN_count.containsKey(tcpPacket.getSourceIP())) {
                            SYN_count.put(tcpPacket.getSourceIP(), SYN_count.get(tcpPacket.getSourceIP()) + 1);
                        } else {
                            SYN_count.put(tcpPacket.getSourceIP(), 1);
                        }
                    }
                    if (tcpPacket.isACK() && tcpPacket.isSYN()) { //SYN ACK
                        if (SYNACK_count.containsKey(tcpPacket.getDestinationIP())) {
                            SYNACK_count.put(tcpPacket.getDestinationIP(), SYNACK_count.get(tcpPacket.getDestinationIP()) + 1);
                        } else {
                            SYNACK_count.put(tcpPacket.getDestinationIP(), 1);
                        }
                    }
                }
                return true;
            }
        });
        for (String ip : SYN_count.keySet()) {
            if (SYN_count.containsKey(ip) && SYNACK_count.containsKey(ip)) {
                if (SYN_count.get(ip) / SYNACK_count.get(ip) >= 3) {
                    System.out.println(ip);
                }

            } else if (SYN_count.get(ip) >= 3 && !SYNACK_count.containsKey(ip)) {
                System.out.println(ip);
            }
        }
        printTime(startTime);
    }

    public static void printTime(long startTime){
        final long duration = System.nanoTime() - startTime;
        long timeInSecond = duration / 1000000000;
        System.out.println("Duration in seconds: " + timeInSecond);
    }

}