/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica3;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.Date;
/**
 *
 * @author tona
 */
public class Analizador {
    private static final String ARCHIVO = "paquetes3.pcap";
    public static void main(String[] args){
        Pcap pcap;
        StringBuilder errbuf = new StringBuilder();
        pcap = Pcap.openOffline(ARCHIVO, errbuf);
        int i = 0;
        if (pcap == null) {
            System.err.println("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            int numeroTrama = 0;
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                System.out.printf("--- #%d Received packet at %s caplen=%-4d len=%-4d %s ---\n", numeroTrama++,
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user                                 // User supplied object
                );
                /*Desencapsulado*/
                for (int i1 = 0; i1 < packet.size(); i1++) {
                    System.out.printf("%02X ", packet.getUByte(i1));
                    if (i1 % 16 == 15)
                        System.out.println("");
                }
                System.out.println("\nEncabezado:\n" + packet.toHexdump());
                byte des[] = packet.getByteArray(0, 6);
                byte src[] = packet.getByteArray(6, 6);
                int longitud = (packet.getUByte(12) << 8) + packet.getUByte(13);

                if (longitud <= 1500) {
                    System.out.println("-----La trama es IEEE802.3-----");
                    System.out.printf("-Tamaño: %d bytes | Valor en la trama: %x\n",
                            longitud, longitud);
                    System.out.printf("-La mac destino es: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            des[0], des[1], des[2], des[3], des[4], des[5]);
                    System.out.printf("-La mac origen es: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            src[0], src[1], src[2], src[3], src[4], src[5]);
                    int ssap = packet.getUByte(15);
                    int dsap = packet.getUByte(14);
                    String CRBit;
                    String IGBit;
                    IGBit = (dsap & 0x00000001) == 1 ? "Grupal" : "Individual";
                    CRBit = (ssap & 0x00000001) == 1 ? "Respuesta" : "Comando";
                    System.out.printf("-IG Bit: %s | Valor: %02X \n", IGBit, dsap);
                    System.out.printf("-CR Bit: %s | Valor: %02X \n", CRBit, ssap);
                    int control = packet.getUByte(16);
                    if ((control & 0x00000011) == 1) {
                        System.out.println("-El control es no numerado");
                    }
                    System.out.printf("-Control: %02X\n", control);

                    System.out.println("");
                } else {
                    System.out.println("\n-----La trama es Ethernet-----\n\n");
                }
            }

        };
        pcap.loop(-1, jpacketHandler, "REDES");
        pcap.close();
    }
}
