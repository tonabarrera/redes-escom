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
            int numeroTrama = 1;
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                System.out.printf("--- #%d Received packet at %s caplen=%-4d len=%-4d %s ---\n", numeroTrama,
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
                    System.out.println("-----La trama numero "+ (numeroTrama++) +" es IEEE802.3-----");
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
                    IGBit = (dsap & 0x1) == 1 ? "Grupal" : "Individual";
                    CRBit = (ssap & 0x1) == 1 ? "Respuesta" : "Comando";
                    System.out.printf("-IG Bit: %s | Valor: %02X \n", IGBit, dsap);
                    System.out.printf("-CR Bit: %s | Valor: %02X \n", CRBit, ssap);
                    int extendido = packet.getByte(17);
                    int control = packet.getByte(16);
                    int PFBit;
                    // comando -Poll
                    // Respuesta - Final
                    if ((control & 0x3) == 0x3) {
                        System.out.printf("-El control es no numerado [%x]\n", control);
                        int SNRM = 0b10000011; //C
                        int SNRME = 0b11001111; //C
                        int SARM_DM = 0b00001111; //C/R
                        int SABM = 0b00101111; //C
                        int SABME = 0b01101111; //C
                        int UI = 0b00000011; //C/R
                        int UA = 0b01100011; //R
                        int DISC_RD = 0b01000011; //C/R
                        int RSET = 0b10001111; //C
                        int XID = 0b10101111; //C/R

                        if((packet.getByte(16) & 0b00010000) == 16){
                            PFBit = 1;
                        }else{
                            PFBit =0;
                        }

                        if (CRBit.equals("Comando")) {
                            if ((control ^ SNRM) == 0 || (control ^ SNRM) == 16) {
                                System.out.println("-Tipo SNRM | Bit P/F => [P="+ PFBit + "]");
                            } else if ((control ^ SNRME) == 0 || (control ^ SNRME) == 16) {
                                System.out.println("-TIpo SNRME | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ SARM_DM) == 0 || (control ^ SARM_DM) == 16) {
                                System.out.println("-Tipo SARM | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ SABM) == 0 || (control ^ SABM) == 16) {
                                System.out.println("-TIpo SABM | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ SABME) == 0 || (control ^ SABME) == 16) {
                                System.out.println("-TIpo SABME | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ UI) == 0 || (control ^ UI) == 16) {
                                System.out.println("-TIpo UI | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ DISC_RD) == 0 || (control ^ DISC_RD) == 16) {
                                System.out.println("-TIpo DISC | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ RSET) == 0 || (control ^ RSET) == 16) {
                                System.out.println("-TIpo RSET | Bit P/F => [P=" + PFBit + "]");
                            } else if ((control ^ XID) == 0 || (control ^ XID) == 16) {
                                System.out.println("-TIpo XID | Bit P/F => [P=" + PFBit + "]");
                            }
                        } else {
                            if ((control ^ SARM_DM) == 0 || (control ^ SARM_DM) == 16) {
                                System.out.println("-TIpo DM | Bit P/F => [F=" + PFBit + "]");
                            } else if ((control ^ UI) == 0 || (control ^ UI) == 16) {
                                System.out.println("-TIpo UI | Bit P/F => [F=" + PFBit + "]");
                            } else if ((control ^ UA) == 0 || (control ^ UA) == 16) {
                                System.out.println("-Tipo UA | Bit P/F => [F=" + PFBit + "]");
                            } else if ((control ^ DISC_RD) == 0 || (control ^ DISC_RD) == 16) {
                                System.out.println("-TIpo RD | Bit P/F => [F=" + PFBit + "]");
                            } else if ((control ^ XID) == 0 || (control ^ XID) == 16) {
                                System.out.println("-TIpo XID | Bit P/F => [F=" + PFBit + "]");
                            }
                        }
                    } else if ((control & 0b11) == 0b01) {
                        System.out.println("-El control es de Supervision");
                        if (extendido == 0) {
                            System.out.printf("-El valor N(R) = %X\n", control >> 5);
                            if((control & 0b00010000) == 16){
                                PFBit = 1;
                            }else{
                                PFBit = 0;
                            }
                            if (CRBit.equals("Comando"))
                                System.out.println("-El Bit P/F => [P=" + PFBit + "]");
                            else
                                System.out.println("-El Bit P/F => [F=" + PFBit + "]");
                        } else {
                            System.out.printf("-El valor N(R) = %X\n", extendido >> 1);
                            if((extendido & 0b1) == 1){
                                PFBit = 1;
                            }else{
                                PFBit = 0;
                            }
                            if (CRBit.equals("Comando"))
                                System.out.println("-El Bit P/F => [P=" + PFBit + "]");
                            else
                                System.out.println("-El Bit P/F => [F=" + PFBit + "]");
                        }
                        // Codigo
                        int RR = 0b00;
                        int REJ = 0b10;
                        int RNR = 0b01;
                        int SREJ = 0b11;
                        if (((control>>2) & 0b11) == RR) {
                            System.out.println("-El tipo es RR");
                        } else if (((control>>2) & 0b11) == REJ) {
                            System.out.println("-El tipo es REJ");
                        } else if (((control>>2) & 0b11) == RNR) {
                            System.out.println("-El tipo es RNR");
                        } else if ((((control>>2) & 0b11) == SREJ) ) {
                            System.out.println("-El tipo es SREJ");
                        }
                    } else if ((control & 0b1) == 0b0) {
                        System.out.println("-El control es de  Informacion");
                        if (extendido == 0) {
                            System.out.printf("-El valor N(R) = %X\n", control >> 5);
                            System.out.printf("-El valor N(S) = %X\n", (control >> 1) & 0b111);

                            if((control & 0b00010000) == 16){
                                PFBit = 1;
                            }else{
                                PFBit = 0;
                            }
                            if (CRBit.equals("Comando"))
                                System.out.println("-El Bit P/F => [P=" + PFBit + "]");
                            else
                                System.out.println("-El Bit P/F => [F=" + PFBit + "]");
                        } else {
                            System.out.printf("-El valor N(R) = %X\n", extendido >> 1);
                            System.out.printf("-El valor N(S) = %X\n", control >> 1);
                            if((extendido & 0b1) == 1){
                                PFBit = 1;
                            }else{
                                PFBit = 0;
                            }
                            if (CRBit.equals("Comando"))
                                System.out.println("-El Bit P/F => [P=" + PFBit + "]");
                            else
                                System.out.println("-El Bit P/F => [F=" + PFBit + "]");
                        }
                    } else
                        System.out.println("***ERROR***");
                    // corrimiento de 8 a 16 y sumar el otro bit
                    System.out.println("");
                } else {
                    System.out.println("\n-----La trama numero: "+ (numeroTrama++) + " es Ethernet-----\n\n");
                }
            }
        };
        pcap.loop(-1, jpacketHandler, "REDES");
        pcap.close();
    }
}
