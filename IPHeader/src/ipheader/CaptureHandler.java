package ipheader;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;

import java.util.Date;

/**
 * Created by tona on 07/06/2017 for IPHeader.
 */
public class CaptureHandler implements PcapPacketHandler<String> {
    private int numeroTrama = 1;

    @Override
    public void nextPacket(PcapPacket packet, String user) {
        System.out.printf("--- #%d Received packet at %s caplen=%-4d len=%-4d %s ---\n",
                numeroTrama++, new Date(packet.getCaptureHeader().timestampInMillis()),
                packet.getCaptureHeader().caplen(),  // Length actually captured
                packet.getCaptureHeader().wirelen(), // Original length
                user);                                 // User supplied object

        System.out.println("\nEncabezado:\n" + packet.toHexdump());
        Ip4 ip4 = new Ip4();
        if (packet.hasHeader(ip4)) {
            System.out.println("Datos del encabezado IPv4");
            System.out.println("Version: " + ip4.version());
            System.out.println("Header length: " +ip4.hlen());
            System.out.println("Type of Service: " + ip4.tos());
            System.out.println("Total length: " +ip4.length());
            System.out.println("Identifier: " + ip4.id());
            System.out.println("Flags: " +ip4.flags());
            System.out.println("Fragment Offset: " + ip4.offset());
            System.out.println("Time to live: " +ip4.ttl());
           // System.out.println("Protocol: " + ip4.pro());
            System.out.println("Header Checksum: " +ip4.checksum());
            System.out.println("Source Address: ");
            for (byte valor : ip4.source())
                System.out.printf("%02X ", valor);
            System.out.println();
            System.out.println("Destination Address: ");
            for (byte valor : ip4.destination())
                System.out.printf("%02X ", valor);
            System.out.println();
            //System.out.println("Options: " + ip4.());
            //System.out.println("Padding: " +ip4());
        }
    }
}
