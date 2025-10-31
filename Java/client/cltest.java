import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class cltest {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    
    private static String clientIndexFile = ""; 
    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        
        // --- 1. Parsing de Argumentos ---
        String clientId = null;
        char[] password = null;
        List<String> commandArgs = new ArrayList<>();

        // Loop para extrair -id e -pwd
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-id")) {
                if (i + 1 < args.length) {
                    clientId = args[++i];
                }
            } else if (arg.equals("-pwd")) {
                if (i + 1 < args.length) {
                    password = args[++i].toCharArray();
                }
            } else {
                // O resto é o comando (PUT, GET, etc.)
                commandArgs.add(arg);
            }
        }

        // --- 2. Validação dos Argumentos ---
        if (clientId == null || password == null) {
            System.err.println("Error: -id and -pwd arguments are mandatory.");
            printUsage();
            return;
        }
        if (commandArgs.isEmpty()) {
            System.err.println("Error: No command specified (PUT, GET, LIST, SEARCH).");
            printUsage();
            return;
        }

        // --- 3. Carregar Índice e CryptoManager ---
        clientIndexFile = "client_index_" + clientId + ".ser";
        loadIndex(); 

        CryptoManager cm = new CryptoManager(password, clientId);
        java.util.Arrays.fill(password, ' '); // Limpar password da RAM

        // --- 4. Conectar e Executar Comando ---
        Socket socket = new Socket("localhost", PORT);
        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        ) {
            
            // O comando é o primeiro argumento *após* a auth
            String cmd = commandArgs.get(0).toUpperCase();
            
            switch (cmd) {
                case "PUT":
                    if (commandArgs.size() < 3) {
                        System.err.println("Error: Missing arguments for PUT.");
                        System.err.println("Usage: ... PUT <path/to/file> <keywords,comma,separated>");
                        return;
                    }
                    File file = new File(commandArgs.get(1));
                    if (!file.exists()) {
                        System.err.println("File not found: " + commandArgs.get(1));
                        return;
                    }
                    List<String> keywords = new ArrayList<>();
                    if (!commandArgs.get(2).trim().isEmpty()) {
                        for (String kw : commandArgs.get(2).split(",")) keywords.add(kw.trim().toLowerCase());
                    }
                    putFile(file, keywords, out, in, cm);
                    break;
            case "GET":
                if (commandArgs.size() < 3) { 
                    System.err.println("Error: Missing arguments for GET.");
                    System.err.println("Usage: ... GET FILE <filename> <path/to/save_dir>");
                    System.err.println("   OR: ... GET KEYWORDS \"keyword1,keyword2,...\" <path/to/save_dir>");
                    System.err.println("   OR: ... GET CHECKINTEGRITY <filename>");
                    return;
                }

                String subCommand = commandArgs.get(1).toUpperCase();
                switch (subCommand) {
                    
                    case "FILE":
                        if (commandArgs.size() < 4) {
                            System.err.println("Usage: ... GET FILE <filename> <path/to/save_dir>");
                            return;
                        }
                        String filename = commandArgs.get(2);
                        String destDirFile = commandArgs.get(3);
                        System.out.println("Retrieving file: " + filename);
                        getFile(filename, destDirFile, out, in, cm);
                        break;
                    
                    case "KEYWORDS":
                        if (commandArgs.size() < 4) {
                            System.err.println("Usage: ... GET KEYWORDS \"keyword1,keyword2,...\" <path/to/save_dir>");
                            return;
                        }
                        String keywordsArg = commandArgs.get(2);
                        String destDirKeywords = commandArgs.get(3);
                        System.out.println("Searching and retrieving files for keywords: " + keywordsArg);
                        List<String> kList = new ArrayList<>();
                        if (!keywordsArg.trim().isEmpty()) {
                            for (String kw : keywordsArg.split(",")) {
                                kList.add(kw.trim().toLowerCase());
                            }
                        }
                        if (kList.isEmpty()) {
                            System.err.println("Error: No keywords provided for search.");
                            break;
                        }
                        getFilesByKeywords(kList, destDirKeywords, out, in, cm);
                        break;

                    case "CHECKINTEGRITY":
                        String filenameCheck = commandArgs.get(2);
                        System.out.println("Checking integrity for file: " + filenameCheck);
                        checkIntegrity(filenameCheck, out, in, cm);
                        break;

                    default:
                        System.err.println("Error: Unknown GET command.");
                        System.err.println("Usage: ... GET [FILE | KEYWORDS | CHECKINTEGRITY] ...");
                        break;
                }
                break;
            case "LIST":
                    System.out.println("Stored files:");
                    for (String f : fileIndex.keySet()) System.out.println(" - " + f);
                    break;

            case "SEARCH":
                if (commandArgs.size() < 2) {
                    System.err.println("Error: Missing arguments for SEARCH.");
                    System.err.println("Usage: ... SEARCH \"keyword1,keyword2,...\"");
                    return;
                }
                
                // Argumento pode ser "keyword1" ou "keyword1,keyword2"
                String keywordsArg = commandArgs.get(1);
                
                // Divide o argumento por vírgulas
                List<String> ksList = new ArrayList<>();
                if (!keywordsArg.trim().isEmpty()) {
                    for (String kw : keywordsArg.split(",")) {
                        ksList.add(kw.trim().toLowerCase());
                    }
                }

                if (ksList.isEmpty()) {
                    System.err.println("Error: No keywords provided for search.");
                    break;
                }
                
                // Chama o novo método searchFiles que aceita uma LISTA
                searchFiles(ksList, out, in, cm);
                break;

            default:
                    System.err.println("Unknown cltest command: " + cmd);
                    printUsage();
                    break;
            }

        } finally {
            saveIndex();
            try {
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeUTF("EXIT");
                out.flush();
            } catch (IOException e) {
                // Socket pode já estar fechada
            }
            socket.close();
        }
    }

    private static void printUsage() {
        System.out.println("cltest: Command-line test client (Non-Interactive)");
        System.out.println("\nUsage: java cltest -id <clientID> -pwd <password> <command> [options]");
        System.out.println("\nCommands:");
        System.out.println("  PUT <file> <keywords>   Upload a file with keywords (e.g., 'key1,key2')");
        System.out.println("  GET <filename> <dir>    Retrieve a file and save it to a directory");
        System.out.println("  LIST                      List all files in the local index");
        System.out.println("  SEARCH <keyword>          Search for files matching a keyword");
    }
    private static void putFile(File file, List<String> keywords, DataOutputStream out, DataInputStream in, CryptoManager cm) throws IOException {
        List<String> blocks = new ArrayList<>();
        String fileId = file.getName();

        try {
            // 1. Generate and store searchable encryption index
            try{
                Map<String, List<byte[]>> secureIndex = cm.generateSearchIndex(fileId, keywords);
                System.out.println("Generated searchable encryption index for " + fileId + " with " + secureIndex.size() + " keyword entries.");
                out.writeUTF("STORE_METADATA");
                out.writeUTF(fileId);
                out.writeInt(secureIndex.size());

                for(Map.Entry<String, List<byte[]>> entry : secureIndex.entrySet()){
                    out.writeUTF(entry.getKey());
                    List <byte[]> fileIdList = entry.getValue();
                    out.writeInt(fileIdList.size());
                    
                    for(byte[] encFileId : fileIdList){
                        out.writeInt(encFileId.length);
                        out.write(encFileId);
                    }
                }
                out.flush();
                String response = in.readUTF();
                if(!response.equals("METADATA_OK")){
                    System.out.println("Error storing metadata index for file: " + fileId);
                    return;
                }
            }catch(Exception e){
                System.out.println("Error for Searchable Encryption Index generation");
            }

            // 2. Encrypt and store file blocks
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[BLOCK_SIZE];
                int bytesRead;
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                
                System.out.println("Storing file blocks:");
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] plaintextBlock = Arrays.copyOf(buffer, bytesRead);
                    byte[] hash = digest.digest(plaintextBlock);
                    String blockId = bytesToHex(hash);
                    
                    byte[] encryptedBlockData = cm.encryptBlock(plaintextBlock);
                    if(encryptedBlockData == null){
                        System.out.println("Encryption failed for block " + blockId);
                        return;
                    }
                    
                    out.writeUTF("STORE_BLOCK");
                    out.writeUTF(blockId);
                    out.writeInt(encryptedBlockData.length);
                    out.write(encryptedBlockData);
                    out.writeInt(0);
                    out.flush();
                    
                    String response = in.readUTF();
                    if (!response.equals("OK")) {
                        System.out.println("Error storing block: " + blockId);
                        return;
                    }
                    blocks.add(blockId);
                    System.out.print(".");
                }
            }
            fileIndex.put(file.getName(), blocks);
            System.out.println();
            System.out.println("File stored with " + blocks.size() + " blocks.");
        
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Erro crítico: Algoritmo SHA-256 não encontrado.");
            e.printStackTrace();
        }
    }
    private static void getFile(String filename, String destPath, DataOutputStream out, DataInputStream in, CryptoManager cm) throws IOException {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
	        System.out.println();	    
            System.out.println("File not found in local index.");
            return;
        }

        File destDir = new File(destPath);
        if (!destDir.exists()) {
            if (!destDir.mkdirs()) {
                System.err.println("Error: Could not create destination directory: " + destPath);
                return;
            }
        }
        String outputFileName = destPath + File.separator + filename;

        try (FileOutputStream fos = new FileOutputStream(outputFileName)) {
            System.out.println("Retrieving and decrypting file blocks:");
            for (String blockId : blocks) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    fos.close();
                    new File(outputFileName).delete(); 
                    return;
                }
                byte[] data = new byte[length];
                in.readFully(data);
		        
                try{
                    byte[] plaintextData = cm.decryptBlock(data);
                    fos.write(plaintextData);
                    System.out.print(".");
                }catch(Exception e){
                    System.out.println("Error during decryption of block " + blockId);
                    System.out.println("The file is corrupt or has been tampered with.");
                    fos.close();
                    new File(outputFileName).delete(); 
                    return;
                }
            }
        }
	    System.out.println();	
        System.out.println("File reconstructed: " + outputFileName);
    }
    private static void searchFiles(List<String> keywords, DataOutputStream out, DataInputStream in, CryptoManager cm) throws IOException {
        try{
            // 1. Gerar todos os tokens primeiro
            List<String> tokens = new ArrayList<>();
            for (String kw : keywords) {
                tokens.add(cm.generateDeterministicToken(kw.toLowerCase()));
            }

            // --- ESTA É A CORREÇÃO ---
            // 2. Enviar o comando "SEARCH" unificado
            out.writeUTF("SEARCH");
            out.writeInt(tokens.size()); // Envia o número de tokens (ex: 1)
            for (String token : tokens) {
                out.writeUTF(token); // Envia cada token
            }
            // --- FIM DA CORREÇÃO ---

            out.flush();

        }catch(Exception e){
            System.out.println("Error generating search tokens.");
            return;
        }
        
        System.out.println();
        System.out.println("Search results for keywords '" + String.join(", ", keywords) + "':");
        
        // 3. Receber os resultados
        try{
            int count = in.readInt(); // AGORA isto vai funcionar!
            if(count == 0){
                // Isto é o que você queria ver:
                System.out.println(" No files found matching ALL keywords.");
                return;
            }

            for (int i = 0; i < count; i++) {
                int length = in.readInt();
                byte[] encFileId = new byte[length];
                in.readFully(encFileId);
                try{
                    byte[] fileIdbytes = cm.decryptConfidential(encFileId);
                    String filename = new String(fileIdbytes, StandardCharsets.UTF_8);
                    System.out.println(" - " + filename);
                }catch(Exception e){
                    System.out.println("Failed to decrypt one search result.");
                    return;
                }
            }
        }catch(Exception e){
            System.out.println("Error receiving search results from server.");
        }
    }
    private static void saveIndex() {
        if (clientIndexFile.isEmpty()) return;
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(clientIndexFile))) {
            oos.writeObject(fileIndex);
        } catch (IOException e) {
            System.err.println("Failed to save index: " + e.getMessage());
        }
    }
    private static void loadIndex() {
        if (clientIndexFile.isEmpty()) return;
        File f = new File(clientIndexFile);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            fileIndex = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Failed to load index: " + e.getMessage());
        }
    }
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    private static void getFilesByKeywords(List<String> keywords, String destDir, DataOutputStream out, DataInputStream in, CryptoManager cm) throws IOException {
        
        // --- 1. Fazer o SEARCH (como no comando SEARCH) ---
        List<String> decryptedFilenames = new ArrayList<>();
        System.out.println("Searching server for files matching ALL keywords: " + String.join(", ", keywords));
        
        try {
            // Gera um token para cada keyword
            List<String> tokens = new ArrayList<>();
            for (String kw : keywords) {
                tokens.add(cm.generateDeterministicToken(kw.toLowerCase()));
            }
            
            out.writeUTF("SEARCH"); // Usa o comando SEARCH unificado
            
            out.writeInt(tokens.size()); // Envia o número de tokens
            for (String token : tokens) {
                out.writeUTF(token); // Envia cada token
            }
            out.flush();

            // Recebe os resultados
            int count = in.readInt();
            if (count == 0) {
                System.out.println("No files found on server matching all keywords.");
                return;
            }

            // Decripta os nomes dos ficheiros encontrados
            System.out.println("Server found " + count + " matching file(s).");
            for (int i = 0; i < count; i++) {
                int length = in.readInt();
                byte[] encFileId = new byte[length];
                in.readFully(encFileId);
                byte[] fileIdbytes = cm.decryptConfidential(encFileId);
                decryptedFilenames.add(new String(fileIdbytes, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            System.err.println("Error during search phase: " + e.getMessage());
            return;
        }

        // --- 2. Fazer o GET para cada ficheiro encontrado ---
        System.out.println("Attempting download...");
        int successCount = 0;
        
        for (String filename : decryptedFilenames) {
            // O cliente só pode descarregar ficheiros que conhece
            if (fileIndex.containsKey(filename)) {
                System.out.println("--- Downloading '" + filename + "' ---");
                // Reutiliza o método 'getFile' (Variante 1) para fazer o download
                getFile(filename, destDir, out, in, cm);
                successCount++;
            } else {
                // Isto pode acontecer se outro cliente também usou esta keyword
                System.out.println("Note: File '" + filename + "' found on server but is not in this client's local index. Skipping.");
            }
        }
        
        System.out.println("Download complete. " + successCount + " file(s) retrieved.");
    }
    private static void checkIntegrity(String filename, DataOutputStream out, DataInputStream in, CryptoManager cm) throws IOException {
        // 1. Encontrar os blocos no índice local
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.err.println("Error: File not found in local index: " + filename);
            return;
        }

        System.out.println("Checking " + blocks.size() + " blocks for " + filename + "...");
        
        try {
            // 2. Recuperar cada bloco e tentar decriptar
            for (int i = 0; i < blocks.size(); i++) {
                String blockId = blocks.get(i);
                
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();

                int length = in.readInt();
                if (length == -1) {
                    System.err.println("  [FAIL] Block " + (i+1) + " (" + blockId + ") not found on server.");
                    return; // Parar a verificação
                }
                
                byte[] data = new byte[length];
                in.readFully(data);
                
                // 3. O PASSO CRUCIAL:
                // O decryptBlock verifica a integridade (tag GCM/Poly1305 ou HMAC)
                // Se falhar, lança uma exceção.
                byte[] plaintextData = cm.decryptBlock(data);
                
                if (plaintextData == null) {
                     // Isto pode acontecer se o HMAC falhar e for tratado internamente
                     throw new SecurityException("Decryption returned null (HMAC failure?).");
                }
                
                System.out.println("  [OK] Block " + (i+1) + " integrity verified.");
            }
            
            System.out.println("\nSUCCESS: All " + blocks.size() + " blocks for " + filename + " are valid.");

        } catch (Exception e) {
            // Se o decryptBlock falhar (ex: AEADBadTagException), a integridade falhou.
            System.err.println("\n  [FAIL] INTEGRITY CHECK FAILED: " + e.getMessage());
            System.err.println("  The file on the server is corrupt or has been tampered with.");
        }
    }

}