/*
 * Author: Edward Herrin
 * Date: 01/31/2020
 * Description: This class exists for the purpose of deriving and storing all of the information pertaining to the
 *  UDP header.
 */
import java.util.Queue;

public class udpData {
    private String sourcePort;
    private String destinationPort;
    private String length;
    private String checksum;
    private StringBuilder data = new StringBuilder();

    public String getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(Queue<Character> packetHexQueue) {
        StringBuilder sourcePortHex = new StringBuilder();
        Character hexVal;
        for(int packetHexIndex = 0; packetHexIndex < 4; packetHexIndex++){
            hexVal = packetHexQueue.remove();
            sourcePortHex.append(hexVal);
        }
        String sourcePortInt = Integer.toString(Integer.parseInt(sourcePortHex.toString(), 16));
        this.sourcePort = sourcePortInt;
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(Queue<Character> packetHexQueue) {
        StringBuilder destinationPortHex = new StringBuilder();
        Character hexVal;
        for(int packetHexIndex = 0; packetHexIndex < 4; packetHexIndex++){
            hexVal = packetHexQueue.remove();
            destinationPortHex.append(hexVal);
        }
        String destinationPortInt = Integer.toString(Integer.parseInt(destinationPortHex.toString(), 16));
        this.destinationPort = destinationPortInt;
    }

    public String getLength() {
        return length;
    }

    public void setLength(Queue<Character> packetHexQueue) {
        StringBuilder lengthHex = new StringBuilder();
        Character hexVal;
        for(int packetHexIndex = 0; packetHexIndex < 4; packetHexIndex++){
            hexVal = packetHexQueue.remove();
            lengthHex.append(hexVal);
        }
        String lengthInt = Integer.toString(Integer.parseInt(lengthHex.toString(), 16));
        this.length = lengthInt;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(Queue<Character> packetHexQueue) {
        StringBuilder checksumHex = new StringBuilder();
        Character hexVal;
        checksumHex.append("0x");
        for(int packetHexIndex = 0; packetHexIndex < 4; packetHexIndex++){
            hexVal = packetHexQueue.remove();
            checksumHex.append(hexVal);
        }
        this.checksum = checksumHex.toString();
    }

    public StringBuilder getData() {
        return data;
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
                data.append("\t\t'").append(asciiString).append("'");
            }
        }
    }

    public udpData(Queue<Character> packetHexQueue) {
        setSourcePort(packetHexQueue);
        setDestinationPort(packetHexQueue);
        setLength(packetHexQueue);
        setChecksum(packetHexQueue);
        setData(packetHexQueue);
    }
}
