/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica2;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot3;


public class Captura {
	/**
	 * Main startup method
	 *
	 * @param args
	 *          ignored
	 */
    // Se le da formato a las direcciones mac
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

    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        /***************************************************************************
        * First get a list of devices on this system
        **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s\n", errbuf.toString());
            return; // Adios popo
        }
		System.out.println("Network devices found:");
        try {
            int i = 0;
            for (PcapIf device : alldevs) {
                String description = (device.getDescription() != null) ? 
                        device.getDescription() : "No description available";
                final byte[] mac = device.getHardwareAddress();
                String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), 
                        description, dir_mac);
            }// final - for
            
            BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("---Elige la interfaz de captura---"); //Tarjeta de red
            int nic = Integer.parseInt(buffer.readLine());
            PcapIf device = alldevs.get(nic); // We know we have at least 1 device
            System.out.printf("\nChoosing '%s' on your behalf:\n", 
                    (device.getDescription() != null) ? device.getDescription() : device.getName());

            /***************************************************************************
             * Second we open up the selected device
             **************************************************************************/
            /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual 
                data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
            Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
            
            if (pcap == null) {
                System.err.printf("Error while opening device for capture: " + errbuf.toString());
                return;
            }//if
            /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression = ""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) //tiene que ser 0
                System.out.println("Filter error: " + pcap.getErr());
            //end if
            pcap.setFilter(filter);
            /****************/

            /***************************************************************************
             * Third we create a packet handler which will receive packets from the
             * libpcap loop.
             **********************************************************************/
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
                @Override
                public void nextPacket(PcapPacket packet, String user) {
                    System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // Length actually captured
                        packet.getCaptureHeader().wirelen(), // Original length
                        user                                 // User supplied object
                        );
                    /******Desencapsulado********/
                    for(int i=0 ; i < packet.size(); i++){
                        System.out.printf("%02X ", packet.getUByte(i));
                        if(i%16==15)
                            System.out.println("");
                    }
                    /* Una forma de hacer la parte de tipo
                    IEEE802dot3 i3e = new IEEE802dot3();
                    if (packet.hasHeader(i3e)) {
                        System.out.printf("\n---Longitud=%04X\n", packet.getUByte(13));
                    } 
                    Ethernet eth = new Ethernet();
                    if (packet.hasHeader(eth)) {
                        System.out.printf("\n---Longitud=%04X\n", packet.getUByte(12));
                        int thisType = eth.type();
                        System.out.printf("\n--Super tipo %04X \n", thisType);
                    }
                    */
                    byte destino[] = packet.getByteArray(0, 6);
                    byte origen[] = packet.getByteArray(6, 6);
                    
                    //packet.getUByte(12) * 256
                    int tipo = (packet.getUByte(12) << 8) + packet.getUByte(13); 

                    System.out.println("\n\nEncabezado: \n" + packet.toHexdump());
                    System.out.printf("-La mac destino es: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                            destino[0], destino[1], destino[2], destino[3], destino[4], destino[5]);
                    System.out.printf("-La mac origen es: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                            origen[0], origen[1], origen[2], origen[3], origen[4], origen[5]);

                    if(tipo <=1500)
                        System.out.println("El tipo es: IEEE.802.3 " + tipo);
                    else
                        System.out.println("El tipo es: Ethernet " + tipo);
                    
                    System.out.println("-------------------------------------------------------\n");
                }
            };
            /***************************************************************************
             * Fourth we enter the loop and tell it to capture 10 packets. The loop
             * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
             * is needed by JScanner. The scanner scans the packet buffer and decodes
             * the headers. The mapping is done automatically, although a variation on
             * the loop method exists that allows the programmer to sepecify exactly
             * which protocol ID to use as the data link type for this pcap interface.
             **************************************************************************/
            pcap.loop(10, jpacketHandler, "jNetPcap rocks!");
            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        } catch(IOException e){e.printStackTrace();}
	}
}
