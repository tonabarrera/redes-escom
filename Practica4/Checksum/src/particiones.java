
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.swing.JFileChooser;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author tevod
 */
public class particiones {
    
    
     public static void splitFile(File f) throws IOException {
        /*int partCounter = 2;//I like to name parts from 001, 002, 003, ...
                            //you can change it to 0 if you want 000, 001, ...

        byte[] sizeOfFiles = new byte[(int)f.length()];// 1MB
        byte[] buffer = new byte[sizeOfFiles];

        try (BufferedInputStream bis = new BufferedInputStream(
                new FileInputStream(f))) {//try-with-resources to ensure closing stream
            String name = f.getName();

            int tmp = 0;
            while ((tmp = bis.read(buffer)) > 0) {
                //write each chunk of data into separate file with different number in name
                File newFile = new File(f.getParent(), name + "."
                        + String.format("%03d", partCounter++));
                try (FileOutputStream out = new FileOutputStream(newFile)) {
                    out.write(buffer, 0, tmp);//tmp is chunk size
                }
            }
        }*/
        Path camino = f.toPath();
        String nombre = f.getName();
        nombre = "C:\\Users\\tevod\\Desktop\\"+nombre;
         
        byte[] tam = Files.readAllBytes(camino);
        
        //byte[] tam = ("Hola").getBytes();
        
         
         int trams = (tam.length)/50;
         
         if((tam.length%50) != 0)
         {
             trams = trams +1;
         }
        
        
        
     
        int cont = 0;
        byte[][] tramas = new byte[trams][50];
        for(int i=0;i<trams;++i)
        {
            for(int j = 0;j<50;++j)
            {
                tramas[i][j] = tam[cont];
                
                if((cont+1)==tam.length)
                {
                    break;
                }
                cont++;     
                
            }
        }
        
        byte[] mensj = new byte[50*trams];
        
        int cont2 = 0;
        
        for(int i=0;i<trams;++i)
        {
            for(int j = 0;j<50;++j)
            {
                mensj[cont2] = tramas[i][j];
                cont2++;
               
            }
        }
        
         //System.out.println(new String(mensj,"UTF-8"));
        
       OutputStream out = new FileOutputStream(nombre);
        out.write(mensj);
        out.close();
        
        
        
        
        //50*i-1 -- 50*i
        
    }

    public static void main(String[] args) throws IOException {
       
        int num = 40;
        System.out.println((byte)num);
        splitFile(new File("C:\\Users\\tevod\\Downloads\\perro.jpg"));
    }
    
}
