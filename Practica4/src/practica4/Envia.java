/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica4;

import org.jnetpcap.*;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
/**
 *0
 * @author tona
 */
public class Envia {
    private static final int NUM_TRAMAS = 2;
    private static Pcap pcap;
    private static Captura capturaHandler;

    private static final int SNAPLEN = 64 * 1024; // Capture all packets, no trucation
    private static final int FLAGS = Pcap.MODE_PROMISCUOUS; // capture all packets
    private static final int TIMEOUT = 10 * 1000; // 10 seconds in millis

    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        String ip_interfaz;

        /*
         * First get a list of devices on this system
         */
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        System.out.println("Dispositivos encontrados:\n");
        int i = 0;
        try{
            for (PcapIf device : alldevs) {
                String description = (device.getDescription() != null) ? device.getDescription()
                                : "No description available";
                final byte[] mac = device.getHardwareAddress();
                String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(),
                                  description, dir_mac);
                Iterator<PcapAddr> it = device.getAddresses().iterator();
                while(it.hasNext()) {
                    PcapAddr dir = it.next();//dir, familia, mascara, bc
                    PcapSockAddr direccion = dir.getAddr();
                    byte[] d_ip = direccion.getData();
                    int familia = direccion.getFamily();
                    int[] ipv4 = new int[4];
                    if(familia == org.jnetpcap.PcapSockAddr.AF_INET) {
                        ipv4[0] = ((int)d_ip[0] < 0) ? ((int)d_ip[0]) + 256 : (int)d_ip[0];
                        ipv4[1] = ((int)d_ip[1] < 0) ? ((int)d_ip[1]) + 256 : (int)d_ip[1];
                        ipv4[2] = ((int)d_ip[2] < 0) ? ((int)d_ip[2]) + 256 : (int)d_ip[2];
                        ipv4[3] = ((int)d_ip[3] < 0) ? ((int)d_ip[3]) + 256 : (int)d_ip[3];

                        System.out.println("IP4-> " + ipv4[0] + "." + ipv4[1] + "." + ipv4[2] + "." + ipv4[3]);
                    } else if(familia == org.jnetpcap.PcapSockAddr.AF_INET6){
                        System.out.print("IP6-> ");
                        for (byte aD_ip : d_ip)
                            System.out.printf("%02X:", aD_ip);
                        System.out.println("");
                    }//if
                }//while
                System.out.println("");
            }//for
        } catch(IOException io){
            io.printStackTrace();
        }
        try{
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Elije la interfaz de red:");
            int interfaz = Integer.parseInt(br.readLine());
            PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device

            Iterator<PcapAddr> it1 = device.getAddresses().iterator();
            while(it1.hasNext()){
                PcapAddr dir = it1.next();//dir, familia, mascara,bc
                PcapSockAddr direccion1 = dir.getAddr();
                byte[] d_ip = direccion1.getData(); //esta sera la ip origen
                int familia = direccion1.getFamily();
                int[] ipv4_1 = new int[4];
                if(familia == org.jnetpcap.PcapSockAddr.AF_INET){
                    ipv4_1[0] = ((int)d_ip[0] < 0) ? ((int)d_ip[0]) + 256 : (int)d_ip[0];
                    ipv4_1[1] = ((int)d_ip[1] < 0) ? ((int)d_ip[1]) + 256 : (int)d_ip[1];
                    ipv4_1[2] = ((int)d_ip[2] < 0) ? ((int)d_ip[2]) + 256 : (int)d_ip[2];
                    ipv4_1[3] = ((int)d_ip[3] < 0) ? ((int)d_ip[3]) + 256 : (int)d_ip[3];
                    ip_interfaz = ipv4_1[0] + "." + ipv4_1[1] + "." + ipv4_1[2] + "." + ipv4_1[3];
                    System.out.println("\nInterfaz que se usara: " + ip_interfaz);
                }
            }

            System.out.print("MAC Origen: ");
            byte[] MACsrc = device.getHardwareAddress();
            for (byte aMACsrc : MACsrc)
                System.out.printf("%02X ", aMACsrc);

            /*
             Second we open a network interface
             */
            pcap = Pcap.openLive(device.getName(), SNAPLEN, FLAGS, TIMEOUT, errbuf);

            /*
             * Third we create our crude packet we will transmit out
             * This creates a broadcast packet
             */
            byte[] trama = new byte[64];
            // Esto es para poner en la trama la MAC destino y origen
            for(int k = 0; k < MACsrc.length; k++){
                trama[k] = (byte) 0xff;
                trama[k+6] = MACsrc[k];
            }

            //NetworkInterface n = NetworkInterface.getByIndex(3);
            ////NetworkInterface n = NetworkInterface.getByName("eth3");
            //System.out.println("iiiiiii: "+device.getDescription());
            //NetworkInterface n = NetworkInterface.getByName(device.getDescription());
            //Enumeration ee = n.getInetAddresses();
            //InetAddress IPorigen=InetAddress.getByName(ip_interfaz);
            //    while (ee.hasMoreElements())
            //    {
            //        InetAddress ii = (InetAddress) ee.nextElement();
            //        System.out.println("IP: "+ii.getHostAddress());
            //        if(ii instanceof java.net.Inet4Address)
            //            IPorigen = ii;
            //    }
            //    /////////////////////////////////////////////////////
            // El tipo que estamos usando es 0x1601
            trama[12] = (byte) 0x16; //tipo sin asignar
            trama[13] = (byte) 0x01; //tipo sin asignar rfc 1340

            //Arrays.fill(a, (byte) 0xff);
            //ByteBuffer b = ByteBuffer.wrap(trama);
            // Aqui empieza la lectura de las tramas que se envian
            /*F I L T R O*/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression = "ether proto 0x1601"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
            /*
             Fourth We send our packet off using open device
             */
            String mensaje;
            byte[] buf;
            int tam;
            capturaHandler = new Captura();

            for(int zz = 0; zz < NUM_TRAMAS; zz++) {
                System.out.println("\nEscribe un mensaje.");
                mensaje = br.readLine();
                buf = mensaje.getBytes();
                tam = buf.length;
                if(tam < 50) {
                    System.arraycopy(buf, 0, trama, 14, tam);
                } else {
                    System.out.println("El mensaje es muy largo... maximo 50 bytes");
                    System.exit(1);
                }
                enviarTrama(trama);
            }
            pcap.close();
        } catch(Exception e){
            e.printStackTrace();
        }//catch
    }

    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0)
                buf.append(':');
            if (b >= 0 && b < 16)
                buf.append('0');
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }

    private static void enviarTrama(final byte trama[]) {
        if (pcap.sendPacket(trama) != Pcap.OK)
            System.err.println(pcap.getErr());
        System.out.println("\n-----Se envio un paquete-----");
        try{
            Thread.sleep(500);
        }catch(InterruptedException e){
            e.printStackTrace();
        }
        pcap.loop(1, capturaHandler, "");
    }
}