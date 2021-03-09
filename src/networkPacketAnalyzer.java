/*
 * Author: Edward Herrin
 * Date: 01/31/2020
 * Description: This program will import a binary file as a string of hexadecimal information. From there, it will
 *  analyze the data by calling on the appropriate classes and will finish with displaying the header and packet
 *  information that was discovered within. In other words, it emulates some of the wireshark packet analyzer
 *  functionality.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Queue;

public class networkPacketAnalyzer {
    public String importFileAsHexString(String fileName){
        String retVal = "";
        try{
            File file = new File(fileName);
            InputStream fileStream = new FileInputStream(file);
            byte[] bytes = null;
            bytes = fileStream.readAllBytes();
            StringBuilder str = new StringBuilder();
            for(byte fileByte : bytes){
                str.append(String.format("%02X", fileByte & 0xFF));
            }
            retVal = str.toString();
            return retVal;
        }catch (IOException e){
            System.out.println("ERROR:" + e);
            return retVal;
        }
    }

    public Queue<Character> enqueuePacketString(String packetHexString){
        Queue<Character> packetHexQueue = new LinkedList<>();
        for(int hexCharIdx = 0; hexCharIdx < packetHexString.length(); hexCharIdx++){
            packetHexQueue.add(packetHexString.charAt(hexCharIdx));
        }
        return packetHexQueue;
    }

    public ArrayList<String> getEthernetHeaderInfo(ethernetHeader pktEthernetHeader){
        ArrayList<String> ethernetHeaderInfo = new ArrayList<>();
        ethernetHeaderInfo.add("---- Ether Header -----");
        ethernetHeaderInfo.add(" ");
        ethernetHeaderInfo.add("Packet size = " + pktEthernetHeader.getPacketSize() + " bytes");
        ethernetHeaderInfo.add("Destination = " + pktEthernetHeader.getDestinationMac() + ",");
        ethernetHeaderInfo.add("Source = " + pktEthernetHeader.getSourceMac() + ",");
        ethernetHeaderInfo.add("EtherType = " + pktEthernetHeader.getEthernetType() + ",");
        ethernetHeaderInfo.add(" ");
        return ethernetHeaderInfo;
    }

    public ArrayList<String> getIpHeaderInfo(ipHeader pktIpHeader){
        ArrayList<String> ipHeaderInfo = new ArrayList<>();
        ipHeaderInfo.add("---- IP Header -----");
        ipHeaderInfo.add(" ");
        ipHeaderInfo.add("Version = " + pktIpHeader.getVersion());
        ipHeaderInfo.add("Header length = " + pktIpHeader.getHeaderLength() + " bytes");
        ipHeaderInfo.add("Differentiated Services Field = 0x" + pktIpHeader.getDiffServField());
        ipHeaderInfo.add("\t" + pktIpHeader.getDscpField()
                + " = " + "Differentiated Services Codepoint: " + pktIpHeader.getDscpName());
        ipHeaderInfo.add("\t" + pktIpHeader.getEcnField()
                + " = " + "Explicit Congestion Notification: " + pktIpHeader.getEcnName());
        ipHeaderInfo.add("Total length = " + pktIpHeader.getTotalLength() + " bytes");
        ipHeaderInfo.add("Identification = " + pktIpHeader.getIdentification());
        ipHeaderInfo.add("Flags = 0x" + pktIpHeader.getFlags());
        ipHeaderInfo.add("\t" + pktIpHeader.getBinFlags().charAt(0)
                + "... .... = Reserved bit: " + pktIpHeader.getIsResBitSet());
        ipHeaderInfo.add("\t." + pktIpHeader.getBinFlags().charAt(1)
                + ".. .... = Don't fragment: " + pktIpHeader.getIsFragSet());
        ipHeaderInfo.add("\t.." + pktIpHeader.getBinFlags().charAt(2)
                + ". .... = More fragments: " + pktIpHeader.getIsMoreFragSet());
        ipHeaderInfo.add("Fragment offset = " + Integer.parseInt(pktIpHeader.getFragOffset().toString(), 2)
                + " bytes");
        ipHeaderInfo.add("Time to live = " + pktIpHeader.getTimeToLive() + " seconds/hops");
        ipHeaderInfo.add("Protocol = " + pktIpHeader.getProtocol() + " (" + pktIpHeader.getProtocolName() + ")");
        ipHeaderInfo.add("Header checksum = 0x" + pktIpHeader.getHeaderChecksum());
        ipHeaderInfo.add("Source address = " + pktIpHeader.getSourceAddress());
        ipHeaderInfo.add("Destination address = " + pktIpHeader.getDestinationAddress());
        ipHeaderInfo.add(pktIpHeader.getOptions());
        ipHeaderInfo.add(" ");
        return ipHeaderInfo;
    }

    public ArrayList<String> getUdpInfo(udpData pktUdpData){
        ArrayList<String> udpInfo = new ArrayList<>();
        udpInfo.add("----- UDP Header -----");
        udpInfo.add(" ");
        udpInfo.add("Source Port = " + pktUdpData.getSourcePort());
        udpInfo.add("Destination port = " + pktUdpData.getDestinationPort());
        udpInfo.add("Length = " + pktUdpData.getLength());
        udpInfo.add("Checksum = " + pktUdpData.getChecksum());
        udpInfo.add(" ");
        udpInfo.add("Data: (first 64 bytes)");
        udpInfo.add(pktUdpData.getData().toString());
        return udpInfo;
    }

    public ArrayList<String> getTcpInfo(tcpData pktTcpData){
        ArrayList<String> tcpInfo = new ArrayList<>();
        tcpInfo.add("----- TCP Header -----");
        tcpInfo.add(" ");
        tcpInfo.add("Source port = " + pktTcpData.getSourcePort());
        tcpInfo.add("Destination port = " + pktTcpData.getDestinationPort());
        tcpInfo.add("Sequence number = " + pktTcpData.getSequenceNumber());
        tcpInfo.add("Acknowledgement number = " + pktTcpData.getAcknowledgementNumber());
        tcpInfo.add("Data offset = " + pktTcpData.getDataOffset() + " bytes");
        tcpInfo.add("Flags = " + pktTcpData.getFlags());
        tcpInfo.add("\t" + pktTcpData.getReservedFlagBin() + " = " + pktTcpData.getReservedFlagName());
        tcpInfo.add("\t" + pktTcpData.getNonceFlagBin() + " = " + pktTcpData.getNonceFlagName());
        tcpInfo.add("\t" + pktTcpData.getCongWinReducedFlagBin() + " = " + pktTcpData.getCongWinReducedFlagName());
        tcpInfo.add("\t" + pktTcpData.getEcnEchoFlagBin() + " = " + pktTcpData.getEncEchoFlagName());
        tcpInfo.add("\t" + pktTcpData.getUrgentFlagBin() + " = " + pktTcpData.getUrgentFlagName());
        tcpInfo.add("\t" + pktTcpData.getAcknowledgementFlagBin() + " = " + pktTcpData.getAcknowledgementFlagName());
        tcpInfo.add("\t" + pktTcpData.getPushFlagBin() + " = " + pktTcpData.getPushFlagName());
        tcpInfo.add("\t" + pktTcpData.getResetFlagBin() + " = " + pktTcpData.getResetFlagName());
        tcpInfo.add("\t" + pktTcpData.getSynFlagBin() + " = " + pktTcpData.getSynFlagName());
        tcpInfo.add("\t" + pktTcpData.getFinFlagBin() + " = " + pktTcpData.getFinFlagName());
        tcpInfo.add("Window = " + pktTcpData.getWindow());
        tcpInfo.add("Checksum = " + pktTcpData.getChecksum());
        tcpInfo.add("Urgent pointer = " + pktTcpData.getUrgentPointer());
        tcpInfo.add(pktTcpData.getOptions());
        tcpInfo.add("TCP Packet Data: (first 64 bytes)");
        tcpInfo.add(pktTcpData.getData());
        return tcpInfo;
    }

    public ArrayList<String> getIcmpInfo(icmpData pktIcmpData){
        ArrayList<String> icmpInfo = new ArrayList<>();
        icmpInfo.add("----- ICMP Header -----");
        icmpInfo.add(" ");
        icmpInfo.add("Type = " + pktIcmpData.getType());
        icmpInfo.add("Code = " + pktIcmpData.getCode());
        icmpInfo.add("Checksum = " + pktIcmpData.getChecksum());
        icmpInfo.add(" ");
        return icmpInfo;
    }


    public static void main(String[] args) {
        for(String arg : args) {
            System.out.println("\nANALYZING FILE: " + arg + "\n");
            networkPacketAnalyzer packetAnalyzer = new networkPacketAnalyzer();
            Queue<Character> packetHexQueue =
                    packetAnalyzer.enqueuePacketString(packetAnalyzer.importFileAsHexString(arg));
            if (!packetHexQueue.isEmpty()) {
                ethernetHeader pktEthernetHeader = new ethernetHeader(packetHexQueue);
                ipHeader pktIpHeader = new ipHeader(packetHexQueue);
                ArrayList<String> ethernetHeaderInfo = packetAnalyzer.getEthernetHeaderInfo(pktEthernetHeader);
                ArrayList<String> ipHeaderInfo = packetAnalyzer.getIpHeaderInfo(pktIpHeader);
                for (String headerDataString : ethernetHeaderInfo) {
                    System.out.println("ETHER:\t" + headerDataString);
                }
                for (String ipDataString : ipHeaderInfo) {
                    System.out.println("   IP:\t" + ipDataString);
                }
                switch (pktIpHeader.getProtocolName()) {
                    case "UDP":
                        udpData pktUdpData = new udpData(packetHexQueue);
                        ArrayList<String> udpInfo = packetAnalyzer.getUdpInfo(pktUdpData);
                        for (String udpDataString : udpInfo) {
                            System.out.println("  UDP:\t" + udpDataString);
                        }
                        break;
                    case "TCP":
                        tcpData pktTcpData = new tcpData(packetHexQueue);
                        ArrayList<String> tcpInfo = packetAnalyzer.getTcpInfo(pktTcpData);
                        for (String tcpDataString : tcpInfo) {
                            System.out.println("  TCP:\t" + tcpDataString);
                        }
                        break;
                    case "ICMP":
                        icmpData pktIcmpData = new icmpData(packetHexQueue);
                        ArrayList<String> icmpInfo = packetAnalyzer.getIcmpInfo(pktIcmpData);
                        for (String icmpDataString : icmpInfo) {
                            System.out.println(" ICMP:\t" + icmpDataString);
                        }
                        break;
                }
            }else{
                System.out.println("\nUsage: java pktanalyzer <dataFilePath1> <dataFilePath2> <dataFilePath3> ...");
            }
        }
    }
}
