package ipheader;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.util.Date;
import java.util.Set;

/**
 * Created by tona on 07/06/2017 for IPHeader.
 */
public class CaptureHandler implements PcapPacketHandler<String> {
    private int numeroTrama = 1;

    @Override
    public void nextPacket(PcapPacket packet, String user) {
        System.out.printf("\n--- #%d Received packet at %s caplen=%-4d len=%-4d %s ---\n",
                numeroTrama++, new Date(packet.getCaptureHeader().timestampInMillis()),
                packet.getCaptureHeader().caplen(),  // Length actually captured
                packet.getCaptureHeader().wirelen(), // Original length
                user);                                 // User supplied object

        Ip4 ip4 = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        if (packet.hasHeader(ip4)) {
            System.out.println("\nEncabezado:\n" + packet.toHexdump());
            System.out.println("Datos del encabezado IPv4");
            System.out.printf("0%s .... = Version: %d\n", Integer.toBinaryString(ip4.version()),
                    ip4.version());
            System.out.printf(".... 0%s = Header length: %d bytes (%X)\n",
                    Integer.toBinaryString(ip4.hlen()), ip4.hlen() * 4, ip4.hlen());
            System.out.printf("0x%02X = Type of service: %s\n", ip4.tos(), ip4.tos());

            System.out.println("Total length: " + ip4.length());
            System.out.printf("Identifier: 0x%04X (%s)\n", ip4.id(), ip4.id());

            System.out.printf("Flags: 0x%02X\n", ip4.flags());
            System.out.printf("%d... .... = Reserved Bit: %s set\n", ip4.flags_Reserved(),
                    (ip4.flags_Reserved() == 1 ? "" : "not"));
            System.out.printf(".%d.. .... = Don't fragment: %s\n", ip4.flags_DF(),
                    ip4.flags_DFDescription());
            System.out.printf("..%d. .... = More fragments: %s\n", ip4.flags_MF(),
                    ip4.flags_MFDescription());

            System.out.println("Fragment Offset: " + ip4.offset());
            System.out.println("Time to live: " + ip4.ttl());
            System.out.printf("Protocol:%s Protocol (%d)\n", ip4.typeDescription().split(":")[1],
                    ip4.type());
            System.out.printf("Header Checksum: 0x%04X\n", ip4.checksum());
            System.out.println("Source Address: ");
            for (int i = 0; i < ip4.source().length; i++) {
                int dato = (ip4.source()[i] < 0) ? (ip4.source()[i] + 256) : ip4.source()[i];
                System.out.print(dato);
                if (i != ip4.source().length - 1) System.out.print(".");
            }
            System.out.println("Destination Address:");
            for (int i = 0; i < ip4.destination().length; i++) {
                int dato = (ip4.destination()[i] < 0) ? ip4.destination()[i] + 256 :
                        ip4.destination()[i];
                System.out.print(dato);
                if (i != ip4.destination().length - 1) System.out.print(".");
            }
            System.out.println();
            if (packet.hasHeader(udp)) {
                System.out.println("UDP");
                System.out.println("Source port: " + udp.source());
                System.out.println("Destination port: " + udp.destination());
                System.out.println("Length: " + udp.length());
                System.out.printf("Checksum: 0x%04X\n", udp.checksum());
            } else if (packet.hasHeader(tcp)) {
                System.out.println("TCP");
                System.out.println("Source port: " + tcp.source());
                System.out.println("Destination port: " + tcp.destination());
                System.out.println("Secuence number: " + tcp.seq());
                System.out.println("Acknowledgment: " + tcp.ack());
                System.out.println("Header length: " + tcp.hlen());

                System.out.printf("Flags: 0x%03X\n", tcp.flags());
                System.out.printf(".... %d... .... = CWR: %s\n", (tcp.flags_CWR() ? 1 : 0),
                        tcp.flags_CWR());
                System.out.printf(".... .%d.. .... = ECN-Echo: %s\n", (tcp.flags_ECE() ? 1 : 0),
                        tcp.flags_ECE());
                System.out.printf(".... ..%d. .... = Urgent: %s\n", (tcp.flags_URG() ? 1 : 0),
                        tcp.flags_URG());
                System.out.printf(".... ...%d .... = Acknowledgment: %s\n",
                        (tcp.flags_ACK() ? 1 : 0), tcp.flags_ACK());
                System.out.printf(".... .... %d... = Push: %s\n", (tcp.flags_PSH() ? 1 : 0),
                        tcp.flags_PSH());
                System.out.printf(".... .... .%d.. = Reset: %s\n", (tcp.flags_RST() ? 1 : 0),
                        tcp.flags_RST());
                System.out.printf(".... .... ..%d. = Syn: %s\n", (tcp.flags_SYN() ? 1 : 0),
                        tcp.flags_SYN());
                System.out.printf(".... .... ...%d = Fin: %s\n", (tcp.flags_FIN() ? 1 : 0),
                        tcp.flags_FIN());
                System.out.println("Window size value: " + tcp.window());
                System.out.printf("Checksum: 0x%04X\n", tcp.checksum());
                System.out.println("Urgent point: " + tcp.urgent());
            }
        }
    }
}
