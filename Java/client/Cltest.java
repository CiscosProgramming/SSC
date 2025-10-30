import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Cltest {
    private void put(){
        //Diretoria fixa do cliente onde esta o ficheiro
        String path = "Java/client/clientfiles";
        File f = new File(path);
        if (!f.exists()) {
            System.out.println("File does not exist.");
            return;
        }
        //Break the file into blocks
        List<String> blocks = new ArrayList<>();
        try(FileInputStream fis = new FileInputStream(f)){
            byte[] buffer = new byte[4096];
            int bytesRead;
            int blockNum = 0;
            while((bytesRead = fis.read(buffer)) != -1){
                //convert byte[] to string for simplicity
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                String blockId = f.getName() + "_block_" + blockNum++;
            
            
            
            }






        }catch(Exception e){
            e.printStackTrace();
        }








        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter keywords for the file:");
        String keywords = scanner.nextLine(); // keywords devem estar separadas por ,

        // scanner para que o cliente escreva as keywords do ficheiro
        //ficheiro guardado em blocos encriptados no servidor
    }

}
