/*
 * Author: Edward Herrin
 * Professor: Samuel Fryer
 * Course: CSCI 351.01
 * Date: 01/31/2020
 * Description: This class exists for the purpose of deriving and storing all of the information pertaining to the
 *  ICMP packet.
 */
import java.util.Queue;

public class icmpData {
    private String type;
    private String code;
    private String checksum;

    public String getHexNibbles(int quantity, Queue<Character> packetHexQueue){
        StringBuilder hexNibbles = new StringBuilder();
        while(quantity != 0){
            hexNibbles.append(packetHexQueue.remove());
            quantity--;
        }
        return hexNibbles.toString();
    }

    public String convertHextoInt(String hexString){
        return Long.toString(Long.parseLong(hexString, 16));
    }

    public String convertHextoBinAndPad(String hexString, int desiredLength){
        StringBuilder binString = new StringBuilder(Long.toBinaryString(Long.parseLong(hexString,16)));
        while (binString.length() < desiredLength){
            binString.insert(0, "0");
        }
        return binString.toString();
    }

    public String getType() {
        return type;
    }

    public void setType(Queue<Character> packetHexQueue) {
        int typeInt = Integer.parseInt(getHexNibbles(2, packetHexQueue), 16);
        switch (typeInt){
            case 0:
                this.type = typeInt + " (Echo Reply)";
                break;
            case 1: case 2: case 7:
                this.type = typeInt + " (Unassigned)";
                break;
            case 3:
                this.type = typeInt + " (Destination Unreachable)";
                break;
            case 4:
                this.type = typeInt + " (Source Quench (Deprecated))";
                break;
            case 5:
                this.type = typeInt + " (Redirect)";
                break;
            case 6:
                this.type = typeInt + " (Alternate Host Address (Deprecated))";
                break;
            case 8:
                this.type = typeInt + " (Echo)";
                break;
            case 9:
                this.type = typeInt + " (Router Advertisement)";
                break;
            case 10:
                this.type = typeInt + " (Router Solicitation)";
                break;
            case 11:
                this.type = typeInt + " (Time Exceeded)";
                break;
            case 12:
                this.type = typeInt + " (Parameter Problem)";
                break;
            case 13:
                this.type = typeInt + " (Timestamp)";
                break;
            case 14:
                this.type = typeInt + " (Timestamp Reply)";
                break;
            case 15:
                this.type = typeInt + " (Information Request (Deprecated))";
                break;
            case 16:
                this.type = typeInt + " (Information Reply (Deprecated))";
                break;
            case 17:
                this.type = typeInt + " (Address Mask Request (Deprecated))";
                break;
            case 18:
                this.type = typeInt + " (Address Mask Reply (Deprecated))";
                break;
            case 19:
                this.type = typeInt + " (Reserved (for Security))";
                break;
            case 30:
                this.type = typeInt + " (Traceroute (Deprecated))";
                break;
            case 31:
                this.type = typeInt + " (Datagram Conversion Error (Deprecated))";
                break;
            case 32:
                this.type = typeInt + " (Mobile Host Redirect (Deprecated))";
                break;
            case 33:
                this.type = typeInt + " (IPv6 Where-Are-You (Deprecated))";
                break;
            case 34:
                this.type = typeInt + " (IPv6 I-Am-Here (Deprecated))";
                break;
            case 35:
                this.type = typeInt + " (Mobile Registration Request (Deprecated))";
                break;
            case 36:
                this.type = typeInt + " (Mobile Registration Reply (Deprecated))";
                break;
            case 37:
                this.type = typeInt + " (Domain Name Request (Deprecated))";
                break;
            case 38:
                this.type = typeInt + " (Domain Name Reply (Deprecated))";
                break;
            case 39:
                this.type = typeInt + " (SKIP (Deprecated))";
                break;
            case 40:
                this.type = typeInt + " (Photuris)";
                break;
            case 41:
                this.type = typeInt + " (ICMP messages utilized by experimental mobility protocols such as Seamoby)";
                break;
            case 42:
                this.type = typeInt + " (Extended Echo Request)";
                break;
            case 43:
                this.type = typeInt + " (Extended Echo Reply)";
                break;
            case 253:
                this.type = typeInt + " (RFC3692-style Experiment 1)";
                break;
            case 254:
                this.type = typeInt + " (RFC3692-style Experiment 2)";
                break;
            case 255:
                this.type = typeInt + " (Reserved)";
                break;
        }
    }

    public String getCode() {
        return code;
    }

    public void setCode(Queue<Character> packetHexQueue) {
        this.code = Integer.toString(Integer.parseInt(getHexNibbles(2, packetHexQueue), 16));
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(Queue<Character> packetHexQueue) {
        this.checksum = "0x" + getHexNibbles(4, packetHexQueue);
    }

    public icmpData(Queue<Character> packetHexQueue) {
        setType(packetHexQueue);
        setCode(packetHexQueue);
        setChecksum(packetHexQueue);
    }
}
