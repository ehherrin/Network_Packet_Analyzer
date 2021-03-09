/*
 * Author: Edward Herrin
 * Professor: Samuel Fryer
 * Course: CSCI 351.01
 * Date: 01/31/2020
 * Description: This class exists for the purpose of deriving and storing all of the information pertaining to the
 *  TCP packet.
 */
import java.util.Queue;

public class tcpData {
    private String sourcePort;
    private String destinationPort;
    private String sequenceNumber;
    private String acknowledgementNumber;
    private String dataOffset;
    private String flags;
    private String reservedFlagBin;
    private String reservedFlagName;
    private String nonceFlagBin;
    private String nonceFlagName;
    private String congWinReducedFlagBin;
    private String congWinReducedFlagName;
    private String ecnEchoFlagBin;
    private String encEchoFlagName;
    private String urgentFlagBin;
    private String urgentFlagName;
    private String acknowledgementFlagBin;
    private String acknowledgementFlagName;
    private String pushFlagBin;
    private String pushFlagName;
    private String resetFlagBin;
    private String resetFlagName;
    private String synFlagBin;
    private String synFlagName;
    private String finFlagBin;
    private String finFlagName;
    private String window;
    private String checksum;
    private String urgentPointer;
    private StringBuilder options = new StringBuilder();
    private StringBuilder data = new StringBuilder();

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

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Queue<Character> packetHexQueue) {
        this.sourcePort = convertHextoInt(getHexNibbles(4, packetHexQueue));
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Queue<Character> packetHexQueue) {
        this.destinationPort = convertHextoInt(getHexNibbles(4, packetHexQueue));;
    }

    public String getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(Queue<Character> packetHexQueue) {
        this.sequenceNumber = convertHextoInt(getHexNibbles(8, packetHexQueue));
    }

    public String getAcknowledgementNumber() {
        return acknowledgementNumber;
    }

    public void setAcknowledgementNumber(Queue<Character> packetHexQueue) {
        this.acknowledgementNumber = convertHextoInt(getHexNibbles(8, packetHexQueue));
    }

    public String getDataOffset() {
        return dataOffset;
    }

    public void setDataOffset(Queue<Character> packetHexQueue) {
        this.dataOffset = Integer.toString(Integer.parseInt(getHexNibbles(1, packetHexQueue), 16) * 4);
    }

    public String getFlags() {
        return flags;
    }

    public void setFlags(Queue<Character> packetHexQueue) {
        String flagsHex = getHexNibbles(3, packetHexQueue);
        String flagsBin = convertHextoBinAndPad(flagsHex, 12);
        String reservedFlagBinStr = flagsBin.substring(0,3);
        int reservedFlagInt = Integer.parseInt(reservedFlagBinStr, 2);
        String nonceFlagBinStr = "" + flagsBin.charAt(3);
        int nonceFlagInt = Integer.parseInt(nonceFlagBinStr, 2);
        String congWinReducedBinStr = "" + flagsBin.charAt(4);
        int congWinReducedInt = Integer.parseInt(congWinReducedBinStr, 2);
        String ecnEchoBinStr = "" + flagsBin.charAt(5);
        int ecnEchoInt = Integer.parseInt(ecnEchoBinStr, 2);
        String urgentFlagBinStr = "" + flagsBin.charAt(6);
        int urgentFlagInt = Integer.parseInt(urgentFlagBinStr, 2);
        String acknowledgementFlagBinStr = "" + flagsBin.charAt(7);
        int acknowledgementFlagInt = Integer.parseInt(acknowledgementFlagBinStr, 2);
        String pushFlagBinStr = "" + flagsBin.charAt(8);
        int pushFlagInt = Integer.parseInt(pushFlagBinStr, 2);
        String resetFlagBinStr = "" + flagsBin.charAt(9);
        int resetFlagInt = Integer.parseInt(resetFlagBinStr, 2);
        String synFlagBinStr = "" + flagsBin.charAt(10);
        int synFlagInt = Integer.parseInt(synFlagBinStr, 2);
        String finFlagBinStr = "" + flagsBin.charAt(11);
        int finFlagInt = Integer.parseInt(finFlagBinStr, 2);
        this.flags = "0x" + flagsHex;
        this.reservedFlagBin = reservedFlagBinStr + ". .... ....";
        this.nonceFlagBin = "..." + nonceFlagBinStr + " .... ....";
        this.congWinReducedFlagBin = ".... " + congWinReducedBinStr + "... ....";
        this.ecnEchoFlagBin = ".... ." + ecnEchoBinStr + ".. ....";
        this.urgentFlagBin = ".... .." + urgentFlagBinStr + ". ....";
        this.acknowledgementFlagBin = ".... ..." + acknowledgementFlagBinStr + " ....";
        this.pushFlagBin = ".... .... " + pushFlagBinStr + "...";
        this.resetFlagBin = ".... .... ." + resetFlagBinStr + "..";
        this.synFlagBin = ".... .... .." + synFlagBinStr + ".";
        this.finFlagBin = ".... .... ..." + finFlagBinStr;
        this.reservedFlagName = reservedFlagInt != 0 ? "Reserved: Set" : "Reserved: Not Set";
        this.nonceFlagName = nonceFlagInt != 0 ? "Nonce: Set" : "Nonce: Not Set";
        this.congWinReducedFlagName = congWinReducedInt != 0 ? "Congestion Window Reduced (CWR): Set"
                : "Congestion Window Reduced (CWR): Not Set";
        this.encEchoFlagName = ecnEchoInt != 0 ? "ECN-Echo: Set" : "ECN-Echo: Not Set";
        this.urgentFlagName = urgentFlagInt != 0 ? "Urgent: Set" : "Urgent: Not Set";
        this.acknowledgementFlagName = acknowledgementFlagInt != 0 ? "Acknowledgment: Set" : "Acknowledgment: Not Set";
        this.pushFlagName = pushFlagInt != 0 ? "Push: Set" : "Push: Not Set";
        this.resetFlagName = resetFlagInt != 0 ? "Reset: Set" : "Reset: Not Set";
        this.synFlagName = synFlagInt != 0 ? "Syn: Set" : "Syn: Not Set";
        this.finFlagName = finFlagInt != 0 ? "Fin: Set" : "Fin: Not Set";
    }

    public String getReservedFlagBin() {
        return reservedFlagBin;
    }

    public String getReservedFlagName() {
        return reservedFlagName;
    }

    public String getNonceFlagBin() {
        return nonceFlagBin;
    }

    public String getNonceFlagName() {
        return nonceFlagName;
    }

    public String getCongWinReducedFlagBin() {
        return congWinReducedFlagBin;
    }

    public String getCongWinReducedFlagName() {
        return congWinReducedFlagName;
    }

    public String getEcnEchoFlagBin() {
        return ecnEchoFlagBin;
    }

    public String getEncEchoFlagName() {
        return encEchoFlagName;
    }

    public String getUrgentFlagBin() {
        return urgentFlagBin;
    }

    public String getUrgentFlagName() {
        return urgentFlagName;
    }

    public String getAcknowledgementFlagBin() {
        return acknowledgementFlagBin;
    }

    public String getAcknowledgementFlagName() {
        return acknowledgementFlagName;
    }

    public String getPushFlagBin() {
        return pushFlagBin;
    }

    public String getPushFlagName() {
        return pushFlagName;
    }

    public String getResetFlagBin() {
        return resetFlagBin;
    }

    public String getResetFlagName() {
        return resetFlagName;
    }

    public String getSynFlagBin() {
        return synFlagBin;
    }

    public String getSynFlagName() {
        return synFlagName;
    }

    public String getFinFlagBin() {
        return finFlagBin;
    }

    public String getFinFlagName() {
        return finFlagName;
    }

    public String getWindow() {
        return window;
    }

    public void setWindow(Queue<Character> packetHexQueue) {
        this.window = convertHextoInt(getHexNibbles(4, packetHexQueue));
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(Queue<Character> packetHexQueue) {
        this.checksum = getHexNibbles(4, packetHexQueue);
    }

    public String getUrgentPointer() {
        return urgentPointer;
    }

    public void setUrgentPointer(Queue<Character> packetHexQueue) {
        this.urgentPointer = convertHextoInt(getHexNibbles(4, packetHexQueue));
    }

    public String getOptions() {
        return options.toString();
    }

    public void setOptions(Queue<Character> packetHexQueue) {
        int optionsLengthBytes = Integer.parseInt(dataOffset, 10) - 20;
        String optionHex;
        this.options.append("Options: (").append(optionsLengthBytes).append(" bytes)");
        while(optionsLengthBytes > 0){
            optionHex = convertHextoInt(getHexNibbles(2, packetHexQueue));
            switch (Integer.parseInt(optionHex, 10)){
                case 1:
                    this.options.append(", No-Operation");
                    optionsLengthBytes--;
                    break;
                case 2:
                    this.options.append(", Maximum Segment Size");
                    optionsLengthBytes = optionsLengthBytes - 2;
                    getHexNibbles(2*4 - 2, packetHexQueue);
                    break;
                case 3:
                    this.options.append(", Window Scale");
                    optionsLengthBytes = optionsLengthBytes - 3;
                    getHexNibbles(2*3 - 2, packetHexQueue);
                    break;
                case 4:
                    this.options.append(", SACK Permitted");
                    optionsLengthBytes = optionsLengthBytes - 2;
                    getHexNibbles(2*2 - 2, packetHexQueue);
                    break;
                case 6:
                    this.options.append(", Echo (obsoleted by option 8)");
                    optionsLengthBytes = optionsLengthBytes - 6;
                    getHexNibbles(2*6 - 2, packetHexQueue);
                    break;
                case 7:
                    this.options.append(", Echo Reply (obsoleted by option 8)");
                    optionsLengthBytes = optionsLengthBytes - 6;
                    getHexNibbles(2*6 - 2, packetHexQueue);
                    break;
                case 8:
                    this.options.append(", Timestamps");
                    optionsLengthBytes = optionsLengthBytes - 10;
                    getHexNibbles(2*10 - 2, packetHexQueue);
                    break;
                case 9:
                    this.options.append(", Partial Order Connection Permitted (obsolete)");
                    optionsLengthBytes = optionsLengthBytes - 2;
                    getHexNibbles(2*2 - 2, packetHexQueue);
                    break;
                case 10:
                    this.options.append(", Partial Order Service Profile (obsolete)");
                    optionsLengthBytes = optionsLengthBytes - 3;
                    getHexNibbles(2*3 - 2, packetHexQueue);
                    break;
                case 14:
                    this.options.append(", TCP Alternate Checksum Request (obsolete)");
                    optionsLengthBytes = optionsLengthBytes - 3;
                    getHexNibbles(2*3 - 2, packetHexQueue);
                    break;
                case 18:
                    this.options.append(", Trailer Checksum Option");
                    optionsLengthBytes = optionsLengthBytes - 3;
                    getHexNibbles(2*3 - 2, packetHexQueue);
                    break;
                case 19:
                    this.options.append(", MD5 Signature Option (obsoleted by option 29)");
                    optionsLengthBytes = optionsLengthBytes - 18;
                    getHexNibbles(2*18 - 2, packetHexQueue);
                    break;
                case 27:
                    this.options.append(", Quick-Start Response");
                    optionsLengthBytes = optionsLengthBytes - 8;
                    getHexNibbles(2*8 - 2, packetHexQueue);
                    break;
                case 28:
                    this.options.append(", User Timeout Option (also, other known unauthorized use)");
                    optionsLengthBytes = optionsLengthBytes - 4;
                    getHexNibbles(2*4 - 2, packetHexQueue);
                    break;
                default:
                    this.options.append(", Unknown");
                    getHexNibbles(2*optionsLengthBytes - 2, packetHexQueue);
                    optionsLengthBytes = 0;
            }
        }
    }

    public String getData() {
        return data.toString();
    }

    public void setData(Queue<Character> packetHexQueue) {
        Character packetHexChar;
        StringBuilder hexString = new StringBuilder();
        StringBuilder asciiString = new StringBuilder();
        int packetHexIndex = 0;
        hexString.append(data.toString().replaceAll("\\s+",""));
        while(!packetHexQueue.isEmpty() && packetHexIndex/2 != 64){
            if(packetHexIndex % 32 == 0 && packetHexIndex != 0){
                for (int hexChar = 0; hexChar < hexString.length(); hexChar+=2) {
                    String str = hexString.substring(hexChar, hexChar+2);
                    asciiString.append((char)Integer.parseInt(str, 16));
                }
                data.append("\t'").append(asciiString).append("'");
                data.append("\n\t\t");
                asciiString.delete(0, asciiString.length());
                hexString.delete(0, hexString.length());
            }
            packetHexChar = packetHexQueue.remove();
            data.append(packetHexChar);
            hexString.append(packetHexChar);
            packetHexIndex++;
            if (packetHexIndex % 4 == 0){
                data.append(" ");
            }
            if(packetHexQueue.isEmpty() || packetHexIndex/2 == 64){
                for (int hexChar = 0; hexChar < hexString.length(); hexChar+=2) {
                    String str = hexString.substring(hexChar, hexChar+2);
                    asciiString.append((char)Integer.parseInt(str, 16));
                }
                while(packetHexIndex % 32 != 0){
                    data.append(" ");
                    if(packetHexIndex % 4 == 0){
                        data.append(" ");
                    }
                    packetHexIndex++;
                }
                data.append("\t'").append(asciiString).append("'");
            }
        }
    }

    public tcpData(Queue<Character> packetHexQueue) {
        setSourcePort(packetHexQueue);
        setDestinationPort(packetHexQueue);
        setSequenceNumber(packetHexQueue);
        setAcknowledgementNumber(packetHexQueue);
        setDataOffset(packetHexQueue);
        setFlags(packetHexQueue);
        setWindow(packetHexQueue);
        setChecksum(packetHexQueue);
        setUrgentPointer(packetHexQueue);
        setOptions(packetHexQueue);
        setData(packetHexQueue);
    }
}
