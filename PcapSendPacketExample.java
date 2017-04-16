import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;  
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
  
public class PcapSendPacketExample {  
    
    private static String asString(final byte[] mac) {
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
    
  public static void main(String[] args) {  
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
    StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
   /***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
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
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
		}//for
                }catch(IOException io){
                  io.printStackTrace();
                }//catch
   try{
       BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
       System.out.println("Elije la interfaz de red:");
       int interfaz = Integer.parseInt(br.readLine());
    PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device  
       System.out.print("MAC ORIGEN: ");   
       byte[] MACo = device.getHardwareAddress();
       for(int j=0;j<MACo.length;j++)
    System.out.printf("%02X ",MACo[j]); 
  
    /***************************************** 
     * Second we open a network interface 
     *****************************************/  
    int snaplen = 64 * 1024; // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000; // 10 seconds in millis  
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
  
    /******************************************************* 
     * Third we create our crude packet we will transmit out 
     * This creates a broadcast packet 
     *******************************************************/  
    byte[] a = new byte[42];
   
    for(int k=0;k<MACo.length;k++){
        a[k] = (byte) 0xff;
        a[k+6]=MACo[k];
    }//for
////////////////////////////////////////////////////////    
//Enumeration e = NetworkInterface.getNetworkInterfaces();
//while(e.hasMoreElements())
//{
//    //
//    NetworkInterface n = (NetworkInterface) e.nextElement();
//    System.out.println("Interfaz: "+n.getName());
//    Enumeration ee = n.getInetAddresses();
//    while (ee.hasMoreElements())
//    {
//        InetAddress ii = (InetAddress) ee.nextElement();
//        System.out.println("IP: "+ii.getHostAddress());
//    }
//}

NetworkInterface n = NetworkInterface.getByName("eth3");
Enumeration ee = n.getInetAddresses();
InetAddress IPorigen=null;
    while (ee.hasMoreElements())
    {
        InetAddress ii = (InetAddress) ee.nextElement();
        System.out.println("IP: "+ii.getHostAddress());
        if(ii instanceof java.net.Inet4Address)
            IPorigen = ii;
    }
    /////////////////////////////////////////////////////
    
    
    a[12]= (byte) 0x08; //tipo
    a[13]= (byte) 0x06; //tipo
    a[14]= (byte) 0x00;  //htipo
    a[15]= (byte) 0x01; //htipo
    a[16]= (byte) 0x08;  //ptipo
    a[17]= (byte) 0x00;  //ptipo
    a[18]= (byte) 0x06;   //hlen
    a[19]= (byte) 0x04;   //plen
    a[20]= (byte) 0x00;   //oper
    a[21]= (byte) 0x01;   //oper
    for(int k=0;k<MACo.length;k++)
      a[k+22]=MACo[k];  //MAC origen
      byte[]IPo =IPorigen.getAddress();
      for(int k=0;k<IPo.length;k++)
      a[k+28]=IPo[k];  //MAC origen
//    a[28]= (byte)255; //ip origen
//    a[29]= (byte)255;
//    a[30]= (byte)255;
//    a[31]= (byte)255;
     for(int k=0;k<MACo.length;k++)
      a[k+32]=(byte) 0xff; //mac destino  
    a[38]= (byte)255;  //ip destino
    a[39]= (byte)255;
    a[40]= (byte)255;
    a[41]= (byte)255;
   
    //Arrays.fill(a, (byte) 0xff);  
    ByteBuffer b = ByteBuffer.wrap(a);  
  
    /******************************************************* 
     * Fourth We send our packet off using open device 
     *******************************************************/  
    if (pcap.sendPacket(b) != Pcap.OK) {  
      System.err.println(pcap.getErr());  
    }  
  
    
    
    /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="arp"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
                                System.out.println("MAC destino:");
                                for(int i=0;i<6;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("MAC origen:");
                                for(int i=6;i<12;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("Tipo:");
                                for(int i=12;i<14;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                int tipo = (packet.getUByte(12)==0)?packet.getUByte(13):(packet.getUByte(12)*256)+packet.getUByte(13);
                                System.out.printf("Tipo= %d",tipo);
                                System.out.println("");
                                
                                for(int i=0;i<packet.size();i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                if(i%16==15)
                                    System.out.println("");
                                }
                                //System.out.println("\n\nEncabezado: "+ packet.toHexdump());
      

			}
		};
    pcap.loop(10, jpacketHandler, "");
    /******************************************************** 
     * Lastly we close 
     ********************************************************/  
    pcap.close();  
    
   }catch(Exception e){
       e.printStackTrace();
   }//catch
  }  
}  
