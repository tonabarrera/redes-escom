package practica4;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.Date;

/**
 * Created by tona on 15/04/2017.
 */
public class Captura implements PcapPacketHandler<String> {
    @Override
    public void nextPacket(PcapPacket packet, String user) {
        System.out.printf("Paquete recibido el %s bytes capturados=%-4d tam original=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user);                                 // User supplied object
        for (int l = 0; l < packet.size(); l++) {
            System.out.printf("%02X ", packet.getUByte(l));
            if (l % 16 == 15)
                System.out.println("");
        }
        System.out.println("\nDesencapsulando...");
                    /*Desencapsulado*/
        System.out.print("-MAC destino: ");
        for (int i = 0; i < 6; i++)
            System.out.printf("%02X ", packet.getUByte(i));

        System.out.print("\n-MAC origen: ");
        for (int i = 6; i < 12; i++) {
            System.out.printf("%02X ", packet.getUByte(i));
        }
        System.out.print("\n-Tipo: 0x");
        for (int i = 12; i < 14; i++) {
            System.out.printf("%02X", packet.getUByte(i));
        }
        int tipo = (packet.getUByte(12) << 8) + packet.getUByte(13);
        System.out.printf("| Tipo: %d", tipo);

        if (tipo == 5633) { //0x1601
            System.out.println("\n-Este es el mensaje que mande: ");
            byte[] t = packet.getByteArray(14, 50);
            for (byte aT : t)
                System.out.printf("%02X ", aT);

            String datos = new String(t);
            System.out.println("\n-Y los datos del mensaje son: " + datos);
        }
    }
}
