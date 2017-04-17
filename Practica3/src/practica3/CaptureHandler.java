package practica3;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.Date;

/**
 * Created by tona on 17/04/2017 for Practica3.
 */

public class CaptureHandler implements PcapPacketHandler<String> {
    private int numeroTrama = 1;

    private static final String[] DSAP = new String[] {"Individual", "Grupal"};
    private static final String[] SSAP = new String[] {"Comando", "Respuesta"};
    private static final String[] POLL_FINAL = new String[] {"P", "F"};
    private static final int COMANDO = 0;
    private static final int RESPUESTA = 1;
    private static final int INDIVIDUAL = 0;
    private static final int GRUPAL = 1;

    private static final int SNRM = 0b10000011; //C
    private static final int SNRME = 0b11001111; //C
    private static final int SARM_DM = 0b00001111; //C/R
    private static final int SABM = 0b00101111; //C
    private static final int SABME = 0b01101111; //C
    private static final int UI = 0b00000011; //C/R
    private static final int UA = 0b01100011; //R
    private static final int DISC_RD = 0b01000011; //C/R
    private static final int RSET = 0b10001111; //C
    private static final int XID = 0b10101111; //C/R

    private static final int RR = 0b00;
    private static final int REJ = 0b10;
    private static final int RNR = 0b01;
    private static final int SREJ = 0b11;

    @Override
    public void nextPacket(PcapPacket packet, String user) {
        int CRBit;
        int IGBit;
        System.out.printf("--- #%d Received packet at %s caplen=%-4d len=%-4d %s ---\n", numeroTrama,
                          new Date(packet.getCaptureHeader().timestampInMillis()),
                          packet.getCaptureHeader().caplen(),  // Length actually captured
                          packet.getCaptureHeader().wirelen(), // Original length
                          user);                                 // User supplied object
                /*Desencapsulado*/
        for (int i = 0; i < packet.size(); i++) {
            System.out.printf("%02X ", packet.getUByte(i));
            if (i % 16 == 15)
                System.out.println("");
        }

        System.out.println("\nEncabezado:\n" + packet.toHexdump());
        byte des[] = packet.getByteArray(0, 6);
        byte src[] = packet.getByteArray(6, 6);
        int longitud = (packet.getUByte(12) << 8) + packet.getUByte(13);

        if (longitud <= 1500) {
            int PFBit;
            System.out.println("-----La trama numero "+ (numeroTrama++) +" es IEEE802.3-----");
            System.out.printf("-Tamaño: %d bytes | Valor en la trama: %x\n",
                              longitud, longitud);
            System.out.printf("-La mac destino es: %02x:%02x:%02x:%02x:%02x:%02x\n",
                              des[0], des[1], des[2], des[3], des[4], des[5]);
            System.out.printf("-La mac origen es: %02x:%02x:%02x:%02x:%02x:%02x\n",
                              src[0], src[1], src[2], src[3], src[4], src[5]);

            int ssap = packet.getUByte(15);
            int dsap = packet.getUByte(14);
            IGBit = (dsap & 0x1) == 1 ? GRUPAL : INDIVIDUAL;
            CRBit = (ssap & 0x1) == 1 ? RESPUESTA : COMANDO;

            System.out.printf("-IG Bit: %s | Valor: %02X \n", DSAP[IGBit], dsap);
            System.out.printf("-CR Bit: %s | Valor: %02X \n", SSAP[CRBit], ssap);
            int extendido = packet.getByte(17);
            int control = packet.getByte(16);
            if (extendido == 0)
                PFBit = getPollFinal(control>>4);
            else
                PFBit = getPollFinal(extendido);

            String tipo = "***ERROR***";
            if ((control & 0b11) == 0b11) {
                System.out.printf("-El control es no numerado [%08d]\n",
                                  Integer.parseInt(Integer.toString(control, 2)));
                tipo = getTypeUnnumered(CRBit, control, tipo);

                System.out.printf("-Tipo %s\n", tipo);
                System.out.printf("-Bit P/F => [%s=%d]\n", POLL_FINAL[CRBit], PFBit);
            } else if ((control & 0b11) == 0b01) {
                if (extendido == 0) {
                    System.out.printf("-El control es de Supervision [%08d]\n",
                                      Integer.parseInt(Integer.toString(control, 2)));
                    System.out.printf("-El valor N(R) = %X\n", control >> 5);
                } else {
                    System.out.printf("-El control es de Supervision [%08d %08d]\n",
                                      Integer.parseInt(Integer.toString(extendido, 2)),
                                      Integer.parseInt(Integer.toString(control, 2)));
                    System.out.printf("-El valor N(R) = %X\n", extendido >> 1);
                }
                tipo = getTypeSupervision(control, tipo);

                System.out.printf("-Tipo %s\n", tipo);
                System.out.printf("-Bit P/F => [%s=%d]\n", POLL_FINAL[CRBit], PFBit);
            } else if ((control & 0b1) == 0b0) {
                if (extendido == 0) {
                    System.out.printf("-El control es de Supervision [%08d]\n",
                                      Integer.parseInt(Integer.toString(control, 2)));
                    System.out.printf("-El valor N(R) = %X\n", control >> 5);
                    System.out.printf("-El valor N(S) = %X\n", (control >> 1) & 0b111);
                } else {
                    System.out.printf("-El control es de Informacion [%08d %08d]\n",
                                      Integer.parseInt(Integer.toString(extendido, 2)),
                                      Integer.parseInt(Integer.toString(control, 2)));
                    System.out.printf("-El valor N(R) = %X\n", extendido >> 1);
                    System.out.printf("-El valor N(S) = %X\n", control >> 1);
                }
                System.out.printf("-Bit P/F => [%s=%d]\n", POLL_FINAL[CRBit], PFBit);
            } else
                System.out.println("***ERROR***");

            System.out.println("");
        } else
            System.out.println("\n-----La trama numero: "+ (numeroTrama++) + " es Ethernet-----\n\n");
    }

    private int getPollFinal(int control){
        return control & 0b1;
    }

    private String getTypeUnnumered(int CRBit, int control, String tipo) {
        if (CRBit == COMANDO) { //Comando
            if ((control ^ SNRM) == 0 || (control ^ SNRM) == 16)
                tipo = "SNRM";
            else if ((control ^ SNRME) == 0 || (control ^ SNRME) == 16)
                tipo = "SNRME";
            else if ((control ^ SARM_DM) == 0 || (control ^ SARM_DM) == 16)
                tipo = "SARM";
            else if ((control ^ SABM) == 0 || (control ^ SABM) == 16)
                tipo = "SABM";
            else if ((control ^ SABME) == 0 || (control ^ SABME) == 16)
                tipo = "SABME";
            else if ((control ^ UI) == 0 || (control ^ UI) == 16)
                tipo = "UI";
            else if ((control ^ DISC_RD) == 0 || (control ^ DISC_RD) == 16)
                tipo = "DISC";
            else if ((control ^ RSET) == 0 || (control ^ RSET) == 16)
                tipo = "RSET";
            else if ((control ^ XID) == 0 || (control ^ XID) == 16)
                tipo = "XID";
        } else { // Respuesta
            if ((control ^ SARM_DM) == 0 || (control ^ SARM_DM) == 16)
                tipo = "DM";
            else if ((control ^ UI) == 0 || (control ^ UI) == 16)
                tipo = "UI";
            else if ((control ^ UA) == 0 || (control ^ UA) == 16)
                tipo = "UA";
            else if ((control ^ DISC_RD) == 0 || (control ^ DISC_RD) == 16)
                tipo = "RD";
            else if ((control ^ XID) == 0 || (control ^ XID) == 16)
                tipo = "XID";
        }
        return tipo;
    }

    private String getTypeSupervision(int control, String tipo) {
        if (((control >> 2) & 0b11) == RR)
            tipo = "RR";
        else if (((control >> 2) & 0b11) == REJ)
            tipo = "REJ";
        else if (((control >> 2) & 0b11) == RNR)
            tipo = "RNR";
        else if (((control >> 2) & 0b11) == SREJ)
            tipo = "SREJ";
        return tipo;
    }
}
