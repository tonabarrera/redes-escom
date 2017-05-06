package captura;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;  
import java.util.Date;
import java.util.List;  
import java.util.logging.Level;
import java.util.logging.Logger;
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class captura {
    static byte[] miMac = new byte[6];
    static byte[] macDestino = new byte[6];
    static int tramas;
    static String nombre;
    static byte[] archivo;
    static int cont=0;
    
    public static void main(String[] args){
        List<PcapIf> alldevs = new ArrayList<PcapIf>();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(alldevs, errbuf);
        
        PcapIf device = alldevs.get(0);
        int snaplen = (64 * 1024); // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000; // 10 seconds in millis  
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
        
    /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ether proto 0x1601"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
   
            
           
                         
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {		
        public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("Paquete capturado el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
                                System.out.println("MAC destino:");
                                for(int i=0;i<6;i++){
                                    miMac[i] = packet.getByte(i);
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("MAC origen:");
                                for(int i=6;i<12;i++){
                                    macDestino[i-6] = packet.getByte(i);
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("Tipo:");
                                for(int i=12;i<14;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                
                                System.out.printf("Tipo= %d",tipo);
                                if(tipo==5633){ //0x1601
                                   System.out.println("\n****************Datos del mensaje:");
                                   byte[]t = packet.getByteArray(14, 50);
                                   
                                    try {
                                        
                                        String datos = new String(t,"UTF-8");
                                        
                                        String[] dats = datos.split("&");
                                        System.out.println(dats[0]);
                                        System.out.println(dats[1]);
                                        tramas = Integer.parseInt(dats[0]);
                                        nombre = dats[1];
                                    } catch (UnsupportedEncodingException ex) {
                                        //Logger.getLogger(captura.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                    
                                    
                                 


                                }

			}
		};
                
                
                
                    try{
                 Thread.sleep(500);
             }catch(InterruptedException e){}
             pcap.loop(1, jpacketHandler, "");
             
            //cachar el archivo
            archivo = new byte[tramas*36];
            
            try
            {
                
                nombre = "C:\\Users\\tevod\\Desktop\\"+nombre;
                
                //String nom = "C:\\Users\\tevod\\Desktop\\"+nomAux;
                OutputStream out = new FileOutputStream(nombre);
                for(int i=0;i<tramas;++i)
                {
                    System.out.println("Trama "+i);
                    PcapPacketHandler<String> packete = new PcapPacketHandler<String>() {	
                    @Override
                    public void nextPacket(PcapPacket packet, String user) {

                                            System.out.printf("Paquete capturado el %s bytes capturados=%-4d tam original=%-4d %s\n",
                                                new Date(packet.getCaptureHeader().timestampInMillis()),
                                                packet.getCaptureHeader().caplen(),  // Length actually captured
                                                packet.getCaptureHeader().wirelen(), // Original length
                                                user                                 // User supplied object
                                                );
                                            /******Desencapsulado********/
                                            byte[] mac1 = new byte[6];
                                            byte[] mac2 = new byte[6];
                                            byte[] mensj = new byte[36];                                          
                                            
                                            System.out.println("Mac Destino");
                                            for(int k=0;k<6;++k)
                                            {
                                                mac1[k] = packet.getByte(k);
                                                System.out.printf("%02X", mac1[k]);
                                            }
                                            
                                             System.out.println("Mac Origen");
                                            for(int k=6;k<12;++k)
                                            {
                                                mac2[k-6] = packet.getByte(k);
                                                System.out.printf("%02X", mac2[k-6]);
                                            }
                                            System.out.println("Tipo");
                                            for(int k=12;k<14;++k)
                                            {
                                                System.out.printf("%02X", packet.getUByte(k));
                                            }
                                            int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                            
                                             if(tipo == 5633)
                                             {
                                                System.out.println("Mensaje");
                                                for(int k=14;k<50;++k)
                                                {
                                                    mensj[k-14] = packet.getByte(k);
                                                    System.out.printf("%02X", mensj[k-14]);
                                                }

                                                try
                                                {
                                                    out.write(mensj);
                                                }catch(Exception ex){}
                                             }
                                      
                                            

                                    }
                            };
                               try{
                             Thread.sleep(5);
                         }catch(InterruptedException e){}
                         pcap.loop(1, packete, "");
                }
                //out.write(archivo);
                out.close();
            }
            catch(Exception ex){
                System.out.println(ex);
            }
            
            
           
    }
    
}
