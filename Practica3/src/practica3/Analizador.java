/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica3;

import org.jnetpcap.Pcap;
/**
 *
 * @author tona
 */
public class Analizador {
    private static final String ARCHIVO = "paquetes3.pcap";

    public static void main(String[] args){
        System.out.printf("Leyendo el archivo [%s]...\n\n", ARCHIVO);
        Pcap pcap;
        StringBuilder errbuf = new StringBuilder();
        pcap = Pcap.openOffline(ARCHIVO, errbuf);
        if (pcap == null) {
            System.err.println("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        CaptureHandler handler = new CaptureHandler();
        pcap.loop(-1, handler, "REDES");
        pcap.close();
    }
}
