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

        Ip4 ip4 = new Ip4();
        if (packet.hasHeader(ip4)) {
            System.out.println("\nEncabezado:\n" + packet.toHexdump());
            System.out.println("Datos del encabezado IPv4");
            System.out.printf("%s .... = Version: %d\n", Integer.toBinaryString(ip4.version()),
                    ip4.version());
            System.out.printf(".... %s Header length: %d bytes (%X)\n",
                    Integer.toBinaryString(ip4.hlen()), ip4.hlen(), ip4.hlen());
            System.out.printf("0x%02X = Type of service: %s\n", ip4.tos(), ip4.tos());
            System.out.println("Total length: " +ip4.length());
            System.out.printf("Identifier: 0x%04X %s\n", ip4.id(), ip4.id());
            System.out.printf("Flags: 0x%02X", ip4.flags());
            System.out.println("Fragment Offset: " + ip4.offset());
            System.out.println("Time to live: " + ip4.ttl());
            System.out.printf("Protocol:%s Protocol (%d)\n", ip4.typeDescription().split(":")[1],
                    ip4.type
                    ());
            System.out.printf("Header Checksum: 0x%04X\n", ip4.checksum());
            System.out.println("Source Address: ");
            for (int i=0; i<ip4.source().length; i++) {
                int dato = (ip4.source()[i]<0) ? ip4.source()[i]+256 : ip4.source()[i];
                System.out.print(dato);
                if (i!=ip4.source().length-1) System.out.print(".");
            }
            System.out.println();
            for (int i=0; i<ip4.destination().length; i++) {
                int dato = (ip4.destination()[i]<0) ? ip4.destination()[i]+256 : ip4.destination()[i];
                System.out.print(dato);
                if (i!=ip4.destination().length-1) System.out.print(".");
            }
            System.out.println();
        }
    }
}
