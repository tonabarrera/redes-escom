/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ipheader;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import static org.jnetpcap.packet.format.FormatUtils.asString;

/**
 *
 * @author tona
 */
public class IPHeader {
    private static final String ARCHIVO = "samples.pcap";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Pcap pcap = null;
        CaptureHandler handler = new CaptureHandler();
        StringBuilder errbuf = new StringBuilder();
        BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("---Elige un mode de captura--");
        System.out.println("0.- Al vuelo");
        System.out.println("1.- De un archivo guardado");
        int opcion = 0;
        try {
            opcion = Integer.parseInt(buffer.readLine());
        } catch (IOException e) {
            e.printStackTrace();
        }
        /*Al vuelo*/
        if (opcion==0) {
            List<PcapIf> alldevs = new ArrayList<>();
            int r = Pcap.findAllDevs(alldevs, errbuf);
            if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                System.err.printf("Can't read list of devices, error is %s\n", errbuf.toString());
                return; // Adios popo
            }
            System.out.println("Network devices found:");
            try {
                int i = 0;
                for (PcapIf device : alldevs) {
                    String description = (device.getDescription() != null) ? device.getDescription() :
                            "No description available";
                    final byte[] mac = device.getHardwareAddress();
                    String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                    System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description,
                            dir_mac);
                }// final - for


                System.out.println("---Elige la interfaz de captura---"); //Tarjeta de red
                int nic = Integer.parseInt(buffer.readLine());
                PcapIf device = alldevs.get(nic); // We know we have at least 1 device
                System.out.printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription() : device.getName());
                int snaplen = 64 * 1024;           // Capture all packets, no trucation
                int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
                int timeout = 10 * 1000;           // 10 seconds in millis
                pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: " + errbuf.toString());
                    return;
                }//if

            /*F I L T R O*/
                PcapBpfProgram filter = new PcapBpfProgram();
                String expression = ""; // "port 80";
                int optimize = 0; // 1 means true, 0 means false
                int netmask = 0;
                int r2 = pcap.compile(filter, expression, optimize, netmask);
                if (r2 != Pcap.OK) //tiene que ser 0
                    System.out.println("Filter error: " + pcap.getErr());
                //end if
                pcap.setFilter(filter);

                pcap.loop(50, handler, "IP HEADER");
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            /*Abrir archivo*/
            pcap = Pcap.openOffline(ARCHIVO, errbuf);
            if (pcap == null) {
                System.err.println("Error while opening device for capture: " + errbuf.toString());
                return;
            }
            pcap.loop(70, handler, "REDES");
        }
        if (pcap != null)
            pcap.close();
    }
    
}
