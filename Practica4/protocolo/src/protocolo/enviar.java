package protocolo;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;  
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;  
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;


public class enviar {
    
    ArrayList<String> interfaces;
    byte trama[];
    byte[] miMac;
    byte[] otraMac;
    
    public enviar()
    {
        interfaces = new ArrayList<>();
        trama = new byte[64];
        miMac = new byte[6];
        otraMac = new byte[6];
    }
    
    public ArrayList getInterfaces()
    {
        return interfaces;
    }

    public void enviaPaquete(int interf,String mac,File f) throws Exception
    {
       List<PcapIf> alldevs = new ArrayList<PcapIf>(); 
       StringBuilder errbuf = new StringBuilder(); // For any error msgs  
       
	int r = Pcap.findAllDevs(alldevs, errbuf);
       
       PcapIf device = alldevs.get(interf);
        int snaplen = (64 * 1024); // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000;
       Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
        String pocs[] = mac.split(":");
       for(int i=0;i<=5;++i)
       {
           trama[i] = (byte)Long.parseLong(pocs[i], 16);
           otraMac[i] = trama[i];
           System.out.printf("%02X", trama[i]);
       }
       miMac = device.getHardwareAddress();
       
       for(int k=0;k<miMac.length;k++){
        trama[k+6]=miMac[k];
       }
        trama[12]= (byte) 0x16; //tipo sin asignar
        trama[13]= (byte) 0x01; //tipo sin asignar rfc 1340 
    
       
       Path camino = f.toPath();
        String nombre = f.getName();
        byte[] tam = Files.readAllBytes(camino);
        
        int trams = (tam.length)/36;
         
         if((tam.length%36) != 0)
         {
             trams = trams +1;
         }  
         
         nombre = trams+"&"+nombre+"&";
         byte[] buf = nombre.getBytes();
         
         if(buf.length<50)
         {
            for(int i=0;i<buf.length;++i)
            {
                trama[14+i]=buf[i];
                //System.out.printf("%02X", trama[14+i]);
            }
         }
          ByteBuffer b = ByteBuffer.wrap(trama);
          PcapBpfProgram filter = new PcapBpfProgram();           String expression ="ether proto 0x1601"; // "port 80";
           int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);  
        
            if (pcap.sendPacket(trama) != Pcap.OK) {  
          System.err.println(pcap.getErr());  
            }
            
            Thread.sleep(500);
        
            int cont=0;
            byte[][] tramas = new byte[trams][36];
            for(int i=0;i<trams;++i)
            {
                for(int j = 0;j<36;++j)
                {
                    tramas[i][j] = tam[cont];

                    if((cont+1)==tam.length)
                    {
                        break;
                    }
                    cont++;     

                }
            }
            
            for(int i = 0;i<trams;++i)
            {
                byte[] envTrama = new byte[50];
                for(int k=0;k<6;++k)
                {
                    envTrama[k] = otraMac[k];
                    envTrama[k+6] = miMac[k];
                }
                envTrama[12]= (byte) 0x16; //tipo sin asignar
                envTrama[13]= (byte) 0x01;
                for(int j=0;j<36;++j)
                {
                    envTrama[14+j]=tramas[i][j];
                }
                b = ByteBuffer.wrap(envTrama);
                 if (pcap.sendPacket(envTrama) != Pcap.OK) {  
                System.err.println(pcap.getErr());  
                  }
                 Thread.sleep(15);
                System.out.println("Envié la trama"+i);
                
                for(int l = 0;l<envTrama.length;++l)
                {
                    System.out.printf("%02X", envTrama[l]);
                }
            }
        //byte[] tam = Files.readAllBytes(camino);
       
        
    }
    
    

    public void listaInterfaces()
    {
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        List<PcapIf> alldevs = new ArrayList<>();

        		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}
                
                

		System.out.println("Dispositivos encontrados:");
		int i = 0;
                try{
		for (PcapIf device : alldevs) {
                    
                    
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        
                        interfaces.add(description +"      MAC: "+ dir_mac);
                        System.out.printf("\n#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);                    
                        
		}//for
                }catch(IOException io){io.printStackTrace();}//catch
    }
    
     private static String asString(final byte[] mac) 
    {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
          if (buf.length() != 0) {
            buf.append(':');
          }
          if (b >= 0 && b < 16) {
            buf.append('0');
          }
          buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }

        return buf.toString();
  }
}
