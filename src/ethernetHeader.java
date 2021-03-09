/*
 * Author: Edward Herrin
 * Professor: Samuel Fryer
 * Course: CSCI 351.01
 * Date: 01/31/2020
 * Description: This class exists for the purpose of deriving and storing all of the information pertaining to the
 *  ethernet header.
 */
import java.util.Queue;

public class ethernetHeader {
    private String packetSize;
    private String destinationMac;
    private String sourceMac;
    private String ethernetType;
    private Integer MAC_BYTES = 6;
    private Integer ETHER_TYPE_BYTES = 2;
    private StringBuilder macAddressBuffer = new StringBuilder();
    private StringBuilder etherTypeBuffer = new StringBuilder();

    public String getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(String packetSize) {
        this.packetSize = packetSize;
    }

    public String getDestinationMac() {
        return destinationMac;
    }

    public String buildMacString(Queue<Character> packetHexQueue){
        if(macAddressBuffer.length() > 0){
            macAddressBuffer.delete(0, macAddressBuffer.length());
        }
        for(int packetHexIdx = 0; packetHexIdx < MAC_BYTES * 2; packetHexIdx++){
            if (packetHexIdx % 2 == 1 && packetHexIdx < MAC_BYTES * 2 - 1) {
                macAddressBuffer.append(packetHexQueue.remove()).append(":");
            } else {
                macAddressBuffer.append(packetHexQueue.remove());
            }
        }
        return macAddressBuffer.toString();
    }

    public void setDestinationMac(Queue<Character> packetHexQueue) {
        this.destinationMac = buildMacString(packetHexQueue);
    }

    public String getSourceMac() {
        return sourceMac;
    }

    public void setSourceMac(Queue<Character> packetHexQueue) {
        this.sourceMac = buildMacString(packetHexQueue);
    }

    public String getEthernetType() {
        return ethernetType;
    }

    public void setEthernetType(Queue<Character> packetHexQueue) {
        for(int packetHexIdx = 0; packetHexIdx < ETHER_TYPE_BYTES * 2; packetHexIdx++){
            etherTypeBuffer.append(packetHexQueue.remove());
        }
        switch (etherTypeBuffer.toString()){
            case "0800":
                this.ethernetType = "IPv4 (0x0800)";
                break;
            case "0806":
                this.ethernetType = "ARP (0x0806)";
                break;
            case "86DD":
                this.ethernetType = "IPv6 (0x86DD)";
                break;
            case "8100":
                this.ethernetType = "IEEE 802.1Q (0x8100)";
                break;
        }
    }

    public ethernetHeader(Queue<Character> packetHexQueue){
        this.setPacketSize(Integer.toString(packetHexQueue.size() / 2));
        this.setDestinationMac(packetHexQueue);
        this.setSourceMac(packetHexQueue);
        this.setEthernetType(packetHexQueue);
    }
}
