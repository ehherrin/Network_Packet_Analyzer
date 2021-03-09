/* Author: Edward Herrin
 * Created: 01/31/2020
 * Description: This program should be compiled by using any standard Java compilation method
 *   (i.e., shell command). Then, one needs only to run the execution command as follows
 *   "java pktanalyzer <dataFilePath1> <dataFilePath2> <dataFilePath3> ..."). If any mistakes are
 *   made, the program will inform the user of the error and will supply a useful usage reminder as standard output to
 *   the console. Lastly, please note that all analysis data will be printed to the console via standard output due to
 *   the lack of specification otherwise.
 */
import java.util.Queue;

public class ipHeader {
    private String version;
    private String headerLength;
    private String diffServField;
    private String dscpField;
    private String ecnField;
    private String dscpName;
    private String ecnName;
    private String totalLength;
    private String identification;
    private String flags;
    private String timeToLive;
    private String protocol;
    private String headerChecksum;
    private String sourceAddress;
    private String destinationAddress;
    private StringBuilder options = new StringBuilder();
    private StringBuilder binFlags = new StringBuilder();
    private String isResBitSet;
    private String isFragSet;
    private String isMoreFragSet;
    private StringBuilder fragOffset = new StringBuilder();
    private String protocolName;

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

    public String getVersion() {
        return version;
    }

    public void setVersion(Queue<Character> packetHexQueue) {
        this.version = Integer.toString(Character.digit(packetHexQueue.remove(), 16));
    }

    public String getHeaderLength() {
        return headerLength;
    }

    public void setHeaderLength(Queue<Character> packetHexQueue) {
        this.headerLength = Integer.toString(Character.digit(packetHexQueue.remove(), 16) * 32 / 8);
    }

    public String getDiffServField() {
        return diffServField;
    }

    public void setDiffServField(Queue<Character> packetHexQueue) {
        String diffServFieldHex = "" + packetHexQueue.remove() + packetHexQueue.remove();
        StringBuilder diffServFieldBin =
                new StringBuilder(Integer.toBinaryString(Integer.parseInt(diffServFieldHex, 16)));
        while(diffServFieldBin.length() < 8){
            diffServFieldBin.insert(0, "0");
        }
        this.diffServField = diffServFieldHex;
        setDscpField(diffServFieldBin.toString());
        setEcnField(diffServFieldBin.toString());
        setDscpName(diffServFieldHex);
        setEcnName(diffServFieldHex);
    }

    public String getDscpField() {
        return dscpField;
    }

    public void setDscpField(String diffServFieldBin) {
        StringBuilder dscpFieldVals = new StringBuilder();
        for(int dscpIndex = 0; dscpIndex < 6; dscpIndex++){
            if (dscpIndex % 4 == 0 && dscpIndex != 0){
                dscpFieldVals.append(" ");
            }
            dscpFieldVals.append(diffServFieldBin.charAt(dscpIndex));
        }
        dscpFieldVals.append("..");
        this.dscpField = dscpFieldVals.toString();
    }

    public String getEcnField() {
        return ecnField;
    }

    public void setEcnField(String diffServFieldBin) {
        StringBuilder ecnFieldVals = new StringBuilder();
        ecnFieldVals.append(".... ..");
        for(int ecnIndex = 6; ecnIndex < 8; ecnIndex++){
            ecnFieldVals.append(diffServFieldBin.charAt(ecnIndex));
        }
        this.ecnField = ecnFieldVals.toString();
    }

    public String getDscpName(){
        return dscpName;
    }

    public void setDscpName(String diffServFieldHex){
        StringBuilder diffServFieldBin =
                new StringBuilder(Integer.toBinaryString(Integer.parseInt(diffServFieldHex, 16)));
        while(diffServFieldBin.length() < 8){
            diffServFieldBin.insert(0, "0");
        }
        StringBuilder dscpNameBin = new StringBuilder();
        for(int bitIdx = 0; bitIdx < 6; bitIdx++){
            dscpNameBin.append(diffServFieldBin.charAt(bitIdx));
        }
        String dscpNameInt = Integer.toString(Integer.parseInt(dscpNameBin.toString(), 2));
        switch (dscpNameInt){
            case "0":
                this.dscpName = "CS0" + " (" + dscpNameInt + ")";
                break;
            case "8":
                this.dscpName = "CS1" + " (" + dscpNameInt + ")";
                break;
            case "16":
                this.dscpName = "CS2" + " (" + dscpNameInt + ")";
                break;
            case "24":
                this.dscpName = "CS3" + " (" + dscpNameInt + ")";
                break;
            case "32":
                this.dscpName = "CS4" + " (" + dscpNameInt + ")";
                break;
            case "40":
                this.dscpName = "CS5" + " (" + dscpNameInt + ")";
                break;
            case "48":
                this.dscpName = "CS6" + " (" + dscpNameInt + ")";
                break;
            case "56":
                this.dscpName = "CS7" + " (" + dscpNameInt + ")";
                break;
            case "10":
                this.dscpName = "AF11" + " (" + dscpNameInt + ")";
                break;
            case "12":
                this.dscpName = "AF12" + " (" + dscpNameInt + ")";
                break;
            case "14":
                this.dscpName = "AF13" + " (" + dscpNameInt + ")";
                break;
            case "18":
                this.dscpName = "AF21" + " (" + dscpNameInt + ")";
                break;
            case "20":
                this.dscpName = "AF22" + " (" + dscpNameInt + ")";
                break;
            case "22":
                this.dscpName = "AF23" + " (" + dscpNameInt + ")";
                break;
            case "26":
                this.dscpName = "AF31" + " (" + dscpNameInt + ")";
                break;
            case "28":
                this.dscpName = "AF32" + " (" + dscpNameInt + ")";
                break;
            case "30":
                this.dscpName = "AF33" + " (" + dscpNameInt + ")";
                break;
            case "34":
                this.dscpName = "AF41" + " (" + dscpNameInt + ")";
                break;
            case "36":
                this.dscpName = "AF42" + " (" + dscpNameInt + ")";
                break;
            case "38":
                this.dscpName = "AF43" + " (" + dscpNameInt + ")";
                break;
            case "46":
                this.dscpName = "EF" + " (" + dscpNameInt + ")";
                break;
            case "44":
                this.dscpName = "VOICE-ADMIT" + " (" + dscpNameInt + ")";
                break;
            default:
                this.dscpName = "Unknown" + " (" + dscpNameInt + ")";
        }
    }

    public String getEcnName() {
        return ecnName;
    }

    public void setEcnName(String diffServFieldHex) {
        StringBuilder diffServFieldBin =
                new StringBuilder(Integer.toBinaryString(Integer.parseInt(diffServFieldHex, 16)));
        while(diffServFieldBin.length() < 8){
            diffServFieldBin.insert(0, "0");
        }
        String ecnNameBin = "" + diffServFieldBin.charAt(6) + diffServFieldBin.charAt(7);
        String ecnNameInt = Integer.toString(Integer.parseInt(ecnNameBin, 2));
        switch (ecnNameInt){
            case "0":
                this.ecnName = "Not-ECT (Not ECN-Capable Transport)" + " (" + ecnNameInt + ")";
                break;
            case "1":
                this.ecnName = "ECT(1) (ECN-Capable Transport(1))" + " (" + ecnNameInt + ")";
                break;
            case "2":
                this.ecnName = "ECT(0) (ECN-Capable Transport(0))" + " (" + ecnNameInt + ")";
                break;
            case "3":
                this.ecnName = "CE (Congestion Experienced)" + " (" + ecnNameInt + ")";
                break;
        }
    }

    public String getTotalLength() {
        return totalLength;
    }

    public void setTotalLength(Queue<Character> packetHexQueue) {
        String totalLengthHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove()
                + packetHexQueue.remove() + packetHexQueue.remove();
        this.totalLength = Integer.toString(Integer.parseInt(totalLengthHexStr, 16));
    }

    public String getIdentification() {
        return identification;
    }

    public void setIdentification(Queue<Character> packetHexQueue) {
        String identificationHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove()
                + packetHexQueue.remove() + packetHexQueue.remove();
        this.identification = Integer.toString(Integer.parseInt(identificationHexStr, 16));
    }

    public String getFlags() {
        return flags;
    }

    public void setFlags(Queue<Character> packetHexQueue) {
        String flagsHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove()
                + packetHexQueue.remove() + packetHexQueue.remove();
        this.flags = flagsHexStr;
    }

    public String getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(Queue<Character> packetHexQueue) {
        String timeToLiveHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove();
        this.timeToLive = Integer.toString(Integer.parseInt(timeToLiveHexStr, 16));
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(Queue<Character> packetHexQueue) {
        String protocolHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove();
        this.protocol = Integer.toString(Integer.parseInt(protocolHexStr, 16));
        setProtocolName(protocol);
    }

    public String getProtocolName() {
        return protocolName;
    }

    public void setProtocolName(String protocol) {
        switch (protocol){
            case "6":
                this.protocolName = "TCP";
                break;
            case "17":
                this.protocolName = "UDP";
                break;
            case "1":
                this.protocolName = "ICMP";
                break;
            default:
                this.protocolName = "Unknown";
                break;
        }
    }

    public String getHeaderChecksum() {
        return headerChecksum;
    }

    public void setHeaderChecksum(Queue<Character> packetHexQueue) {
        String headerChecksumHexStr = "" + packetHexQueue.remove() + packetHexQueue.remove()
                + packetHexQueue.remove() + packetHexQueue.remove();
        this.headerChecksum = headerChecksumHexStr;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public String getAddress(Queue<Character> packetHexQueue) {
        StringBuilder addressOctet = new StringBuilder();
        for(int octetIndex = 0; octetIndex < 4; octetIndex++){
            addressOctet.append(Integer.parseInt(
                    "" + packetHexQueue.remove() + packetHexQueue.remove(), 16));
            if(octetIndex < 3){
                addressOctet.append(".");
            }
        }
        return addressOctet.toString();
    }

    public void setSourceAddress(Queue<Character> packetHexQueue) {
        this.sourceAddress = getAddress(packetHexQueue);
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public void setDestinationAddress(Queue<Character> packetHexQueue) {
        this.destinationAddress = getAddress(packetHexQueue);
    }

    public String getOptions() {
        return options.toString();
    }

    public void setOptions(Queue<Character> packetHexQueue) {
        if(Integer.parseInt(headerLength) > 20){
            int optionsLengthBytes = 4;
            String optionHex;
            this.options.append("Options: ( ").append(optionsLengthBytes).append(" bytes)");
            while(optionsLengthBytes > 0){
                optionHex = convertHextoInt(getHexNibbles(2, packetHexQueue));
                switch (Integer.parseInt(optionHex, 10)){
                    case 0:
                        this.options.append(", EOOL");
                        optionsLengthBytes--;
                        break;
                    case 1:
                        this.options.append(", NOP");
                        optionsLengthBytes--;
                        break;
                    case 7:
                        this.options.append(", RR");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 10:
                        this.options.append(", ZSU");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 11:
                        this.options.append(", MTUP");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 12:
                        this.options.append(", MTUR");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 15:
                        this.options.append(", ENCODE");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 25:
                        this.options.append(", QS");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 30:
                        this.options.append(", EXP");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 68:
                        this.options.append(", TS");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 82:
                        this.options.append(", TR");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 94: case 158: case 222:
                        this.options.append(", EXP");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 130:
                        this.options.append(", SEC");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 131:
                        this.options.append(", LSR");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 133:
                        this.options.append(", E-SEC");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 134:
                        this.options.append(", CIPSO");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 136:
                        this.options.append(", SID");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 137:
                        this.options.append(", SSR");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 142:
                        this.options.append(", VISA");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 144:
                        this.options.append(", IMITD");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 145:
                        this.options.append(", EIP");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 147:
                        this.options.append(", ADDEXT");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 148:
                        this.options.append(", RTRALT");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 149:
                        this.options.append(", SDB");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 151:
                        this.options.append(", DPS");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 152:
                        this.options.append(", UMP");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    case 205:
                        this.options.append(", FINN");
                        optionsLengthBytes = optionsLengthBytes - 4;
                        convertHextoInt(getHexNibbles(6, packetHexQueue));
                        break;
                    default:
                        this.options.append(", Unknown");
                        getHexNibbles(2*optionsLengthBytes - 2, packetHexQueue);
                        optionsLengthBytes = 0;
                }
            }
        }else {
            this.options.append("No options");
        }
    }

    public void setFlagInfo(){
        binFlags.append(Integer.toBinaryString(Integer.parseInt(flags, 16)));
        while (binFlags.length() < 16){
            binFlags.insert(0, "0");
        }
        isResBitSet = binFlags.charAt(0) == '1' ? "Set" : "Not Set";
        isFragSet = binFlags.charAt(1) == '1' ? "Set" : "Not Set";
        isMoreFragSet = binFlags.charAt(2) == '1' ? "Set" : "Not Set";
        for(int binValIdx = 3; binValIdx < binFlags.length(); binValIdx++){
            fragOffset.append(binFlags.charAt(binValIdx));
        }
    }

    public StringBuilder getBinFlags() {
        return binFlags;
    }

    public String getIsResBitSet() {
        return isResBitSet;
    }

    public String getIsFragSet() {
        return isFragSet;
    }

    public String getIsMoreFragSet() {
        return isMoreFragSet;
    }

    public StringBuilder getFragOffset() {
        return fragOffset;
    }

    public ipHeader(Queue<Character> packetHexQueue){
        this.setVersion(packetHexQueue);
        this.setHeaderLength(packetHexQueue);
        this.setDiffServField(packetHexQueue);
        this.setTotalLength(packetHexQueue);
        this.setIdentification(packetHexQueue);
        this.setFlags(packetHexQueue);
        this.setFlagInfo();
        this.setTimeToLive(packetHexQueue);
        this.setProtocol(packetHexQueue);
        this.setHeaderChecksum(packetHexQueue);
        this.setSourceAddress(packetHexQueue);
        this.setDestinationAddress(packetHexQueue);
        this.setOptions(packetHexQueue);
    }

}
