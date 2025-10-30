import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets; // Para codificação/decodificação Base64
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;     // Para geração segura de números aleatórios (essencial para KeyGenerator)
import java.util.Base64;               // Para codificar a chave em Base64 antes de guardar
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.nio.file.Files;             // Para ler/escrever o ficheiro da chave (operação simples)
import java.nio.file.Paths;         // Para utilitário de caminhos de ficheiro

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator; //Gerar key
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec; //converter byte[] em SecretKey
import javax.crypto.SecretKey; //Representar chave secreta

import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;


public class CryptoManager {
    
    private int key;
    private String algorithm;
    private SecureRandom secureRandom;
    private SecretKey sKey; //Encryption
    private SecretKey hmac; //Authentication
    private boolean hasHmac = false;
    private String clienteId; //ID do cliente para identificar a key
    private char[] pwd;
    private static final int GCM_IV_LENGTH = 12;    // 96 bits
    private static final int GCM_TAG_LENGTH = 16;   //128 bits
    // private final String KEY_DIR = "Java/client/KeyStore/"; //Diretoria para guardar a chave
    private final String KEY_DIR = "KeyStore/"; //Diretoria para guardar a chave
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private SecretKey seKey;

    
    //Criar palavra passe para gerar uma master key que desencripta as outras keys em KeyStore
    // A palavra passe e fornecida pelo utilizador na inicialização do cliente
    // tera que ser sempre a mesma caso contrario a master key calculada sera diferente e as keys nao poderao ser desencriptadas

    public CryptoManager(char[] pwd, String clienteId){
        this.clienteId = clienteId;
        this.pwd = pwd;
        secureRandom = new SecureRandom();
        try {
            loadFile();
            File keyFile = new File(KEY_DIR + this.clienteId + "~" + algorithm +"~enc.key");//Verificar se a key ja existe
            if(!keyFile.exists()){
                createKey();
                storeKey();
            }else{
                loadKeys();
            }    
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("Error loading crypto configuration or creating key");
        } finally {
            //Limpar a password da memória por motivos de segurança
            /* if (this.pwd != null) {
                java.util.Arrays.fill(pwd, ' ');
                pwd = null;
            }
            */
        }
    }
    private void loadFile() throws IOException{
        File crypto = new File("cryptoconfig.txt");
            //Check
            if(!crypto.exists()){
                throw new IOException("Crypto configuration file not found.");
            }
        try(BufferedReader reader = new BufferedReader(new FileReader(crypto))){
            //Primeira linha
            String algorithm = reader.readLine();
                //Check
                if(algorithm == null || algorithm.isEmpty()){
                    throw new IOException("Algorithm not specified in configuration file.");
                }
            this.algorithm = algorithm.trim();//Atribuir valor do algoritmo à variavel algorithm

            //Segunda linha
            String keysizeLine = reader.readLine();
            String keysize = keysizeLine.trim();
            String[] l2 = keysize.split(" ");
                //Check
                if(l2.length != 3){
                    throw new IOException("Key size not properly specified in configuration file.");
                }
            key = Integer.parseInt(l2[1]); //Atribuir valor da chave à variavel key
            
        }
    }
    private void createKey() throws NoSuchAlgorithmException{
        switch(algorithm){
            case "AES GCM":
                //Generate AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(key,secureRandom);
                sKey = kg.generateKey();
                System.out.println("Generated AES key of size " + key + " bits.");
                break;
            case "AES CBC PKCS5Padding":
                //Generate AES key
                KeyGenerator a = KeyGenerator.getInstance("AES");
                a.init(key,secureRandom);
                sKey = a.generateKey();
                KeyGenerator h = KeyGenerator.getInstance("HmacSHA256");
                h.init(key,secureRandom);
                hmac = h.generateKey();
                hasHmac = true;
                System.out.println("Generated AES key of size " + key + " bits.");
                System.out.println("Generated HMAC key of size " + key + " bits.");
                break;
            case "CHACHA20 Poly1305":
                //Generate ChaCha20 key
                int chachasize = 256;
                KeyGenerator c = KeyGenerator.getInstance("CHACHA20");
                c.init(chachasize,secureRandom);
                sKey = c.generateKey();
                System.out.println("Generated ChaCha20-Poly1305 key of size 256");
                break;
            default:
                throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
        }
        KeyGenerator SeK = KeyGenerator.getInstance("AES");
        SeK.init(256, secureRandom);
        this.seKey = SeK.generateKey();
        System.out.println("Generated Searchable Encryption key of size 256 bits.");
    }
    private SecretKey getMKey(byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(this.pwd, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec);
    }
    private byte[] encryptMasterKey(SecretKey masterKey, SecretKey kek, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv); // Tag em bits
        // Inicializa a cifra com a KEK (Chave de Proteção)
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek.getEncoded(), "AES"), gcmSpec);
        // O doFinal() em GCM produz o Ciphertext e anexa a Tag de Autenticação (16B)
        byte[] encryptedMasterKeyWithTag = cipher.doFinal(masterKey.getEncoded());
        // Empacota o IV e o resultado (Ciphertext + Tag)
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedMasterKeyWithTag.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedMasterKeyWithTag);
        return byteBuffer.array();
    }
    private void protectKey(byte[] salt, byte[] encryptMasterKeyWithIv, String filename) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + encryptMasterKeyWithIv.length);
        byteBuffer.put(salt);
        byteBuffer.put(encryptMasterKeyWithIv);
        String encodedData = Base64.getEncoder().encodeToString(byteBuffer.array());
        Files.write(Paths.get(filename), encodedData.getBytes(StandardCharsets.UTF_8));
    }
    private void storeKey(){
        try{
            //Gerar salt
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);
            //KEK
            SecretKey kek = getMKey(salt);
            String KeyFileEnc = KEY_DIR + this.clienteId + "~" + algorithm + "~enc.key"; 
            String KeyFileAuth = KEY_DIR + this.clienteId + "~" + algorithm + "~auth.key";
            String KeyFileSe = KEY_DIR + this.clienteId + "~" + algorithm + "~se.key";
            //Guardar chave de encriptação
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            byte[] encryptedData = encryptMasterKey(sKey, kek, iv);
            protectKey(salt, encryptedData, KeyFileEnc);
            System.out.println("Encryption key stored successfully in " + KeyFileEnc);
            //Guardar chave de pesquisa segura
            if(this.seKey != null){
                byte[] iv_se = new byte[GCM_IV_LENGTH];
                secureRandom.nextBytes(iv_se);
                byte[] encryptedDataSe = encryptMasterKey(this.seKey, kek, iv_se);
                protectKey(salt, encryptedDataSe, KeyFileSe);
                System.out.println("Searchable Encryption key stored successfully in " + KeyFileSe);
            }



            //Guardar chave de autenticação se existir
            if(hasHmac){
                byte[] iv_hmac = new byte[GCM_IV_LENGTH];
                secureRandom.nextBytes(iv_hmac);
                byte[] encryptedDataAuth = encryptMasterKey(hmac, kek, iv_hmac);
                protectKey(salt, encryptedDataAuth, KeyFileAuth);
                System.out.println("HMAC key stored successfully in " + KeyFileAuth);
            }
        }catch(Exception e){
            System.err.println("Error storing keys: " + e.getMessage());
        }
    
    }
    private void loadKeys(){
        
        if (sKey != null && (!hasHmac || (hasHmac && hmac != null))) {
        // Both keys are already in memory, no need to re-load
        return;
    }
        
        
        File dir = new File(KEY_DIR);
        File[] files = dir.listFiles((d, name) -> name.startsWith(this.clienteId));
        
        if (!dir.exists() || !dir.isDirectory()) {
        System.err.println("[ERROR] Key directory not found: " + dir.getAbsolutePath());
        return;
        }
        
        //Check
        if (files == null || files.length == 0) {
            System.err.println("No key files found for client ID: " + this.clienteId);
            return;
        }
        for(File f : files ){
            try{
                byte[] encodedKeyData = Files.readAllBytes(f.toPath());
                byte[] decodedKeyData = Base64.getDecoder().decode(encodedKeyData);
                ByteBuffer byteBuffer = ByteBuffer.wrap(decodedKeyData);
                byte[] salt = new byte[SALT_LENGTH];
                byteBuffer.get(salt);
                SecretKey kek = getMKey(salt); //derives KEK from password and salt
                byte[] iv = new byte[GCM_IV_LENGTH];
                byteBuffer.get(iv);
                byte[] encryptedKeyWithTag = new byte[byteBuffer.remaining()];
                byteBuffer.get(encryptedKeyWithTag);
                SecretKey originalKey = decryptMasterKey(encryptedKeyWithTag, kek, iv);

                //Key assignment
                if(f.getName().endsWith("enc.key")){
                    sKey = originalKey;
                    System.out.println("Encryption key loaded successfully from " + f.getName());
                }else if(f.getName().endsWith("auth.key")){
                    hmac = originalKey;
                    hasHmac = true;
                    System.out.println("HMAC key loaded successfully from " + f.getName());
                }else if(f.getName().endsWith("se.key")){
                    seKey = originalKey;
                    System.out.println("Searchable Encryption key loaded successfully from " + f.getName());
                }
            }catch(Exception e){
                System.err.println("Error loading key from file " + f.getName() + ": " + e.getMessage()); // Debug
            }
        }
    }
    private SecretKey decryptMasterKey(byte[] encryptedKeyWithTag, SecretKey kek, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv); // Tag em bits
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek.getEncoded(), "AES"), gcmSpec);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKeyWithTag);
        return new SecretKeySpec(decryptedKeyBytes, "AES");



    }
    public byte[] encryptBlock(byte[] plaintext){
        byte[] cipherBlock = null;
        try{        
                //loadKeys();// Load the keys and decrypt them so that we can now encrypt data with them
                switch(algorithm){
                    case "AES GCM":
                        byte[] iv = new byte[GCM_IV_LENGTH];
                        secureRandom.nextBytes(iv);
                        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                        cipher.init(Cipher.ENCRYPT_MODE, sKey, gcmSpec);
                        byte[] cipherText = cipher.doFinal(plaintext);

                        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
                        byteBuffer.put(iv);
                        byteBuffer.put(cipherText);
                        cipherBlock = byteBuffer.array();
                        break;
                    case "AES CBC PKCS5Padding":
                        byte[] ivCbc = new byte[16];
                        secureRandom.nextBytes(ivCbc);
                        Cipher cipherCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherCbc.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(ivCbc));
                        byte[] cipherTextCbc = cipherCbc.doFinal(plaintext);
                        
                        ByteBuffer byteBufferCbc = ByteBuffer.allocate(ivCbc.length + cipherTextCbc.length);
                        byteBufferCbc.put(ivCbc);
                        byteBufferCbc.put(cipherTextCbc);
                        byte [] combined = byteBufferCbc.array();

                        if(hasHmac){
                            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                            mac.init(hmac);
                            byte[] hmacValue = mac.doFinal(combined);

                            ByteBuffer finalBuffer = ByteBuffer.allocate(combined.length + hmacValue.length);
                            finalBuffer.put(combined);
                            finalBuffer.put(hmacValue);
                            cipherBlock = finalBuffer.array();
                        }else{
                            System.err.println("HMAC key not available for AES/CBC authentication.");
                        }
                        break;
                    case "CHACHA20 Poly1305":
                        byte[] nonce = new byte[12];
                        secureRandom.nextBytes(nonce);
                        Cipher chachaCipher = Cipher.getInstance("ChaCha20-Poly1305");
                        chachaCipher.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(nonce));
                        byte[] cipherTextChaCha = chachaCipher.doFinal(plaintext);

                        ByteBuffer chaChaBuffer = ByteBuffer.allocate(nonce.length + cipherTextChaCha.length);
                        chaChaBuffer.put(nonce);
                        chaChaBuffer.put(cipherTextChaCha);
                        cipherBlock = chaChaBuffer.array();
                        break;
                    default:
                        System.err.println("Unsupported algorithm for encryption: " + algorithm + " Encryption Block failed.");
                }
        }catch(Exception e){
            System.err.println("Error during block encryption: " + e.getMessage());
        }
        return cipherBlock;
    }
    public byte[] decryptBlock(byte[] cipherBlock){
        byte[] plainText = null;
        try{
            //loadKeys();
            switch(algorithm){
                case "AES GCM":
                    ByteBuffer byteBuffer = ByteBuffer.wrap(cipherBlock);
                    byte[] iv = new byte[GCM_IV_LENGTH];
                    byteBuffer.get(iv);
                    byte[] cipherText = new byte[byteBuffer.remaining()];
                    byteBuffer.get(cipherText);
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
                    cipher.init(Cipher.DECRYPT_MODE, sKey, gcmSpec);
                    plainText = cipher.doFinal(cipherText);
                    break;
                case "AES CBC PKCS5Padding":
                    ByteBuffer byteBufferCbc = ByteBuffer.wrap(cipherBlock);
                    byte[] ivCbc = new byte[16];
                    byteBufferCbc.get(ivCbc);
                    byte[] cipherTextCbc = new byte[byteBufferCbc.remaining()];
                    byteBufferCbc.get(cipherTextCbc);
                    if (hasHmac){
                        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                        mac.init(hmac);
                        int hmacLength = mac.getMacLength();
                        int cipherTextLength = cipherTextCbc.length - hmacLength;
                        byte[] ciphertextWithIV = new byte[ivCbc.length + cipherTextLength];
                        System.arraycopy(ivCbc, 0, ciphertextWithIV, 0, ivCbc.length);
                        System.arraycopy(cipherTextCbc, 0, ciphertextWithIV, ivCbc.length, cipherTextLength);
                        byte[] receivedHmac = new byte[hmacLength];
                        System.arraycopy(cipherTextCbc, cipherTextLength, receivedHmac, 0, hmacLength);
                        byte[] computedHmac = mac.doFinal(ciphertextWithIV);
                        if(!java.util.Arrays.equals(receivedHmac, computedHmac))
                            throw new SecurityException("HMAC verification failed. Data integrity compromised.");    
                        Cipher cipherCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        cipherCbc.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(ivCbc));
                        plainText = cipherCbc.doFinal(cipherTextCbc, 0, cipherTextLength);
                    }else{
                        System.err.println("HMAC key not available for AES/CBC authentication.");
                    }
                    break;
                case "CHACHA20 Poly1305":
                    ByteBuffer chaChaBuffer = ByteBuffer.wrap(cipherBlock);
                    byte[] nonce = new byte[12];
                    chaChaBuffer.get(nonce);
                    byte[] cipherTextChaCha = new byte[chaChaBuffer.remaining()];
                    chaChaBuffer.get(cipherTextChaCha);
                    Cipher chachaCipher = Cipher.getInstance("ChaCha20-Poly1305");
                    chachaCipher.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(nonce));
                    plainText = chachaCipher.doFinal(cipherTextChaCha);
                    break;
                default:
                    System.err.println("Unsupported algorithm for decryption: " + algorithm + " Decryption Block failed.");
            }
        }catch(Exception e){
            System.err.println("Error during block decryption: " + e.getMessage());
        }
        return plainText;
    }

    public Map<String, List<byte[]>> generateSearchIndex(String fileId, List<String> keywords) throws Exception {
        Map<String, List<byte[]>> searchIndex = new HashMap<>();
        //Check
        if(this.seKey == null){
            System.err.println("Searchable Encryption key not initialized. - CryptoManager");
        }
        byte[] fileIdBytes = fileId.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedFileId = encryptConfidential(fileIdBytes);

        List<byte[]> fileIdList = new java.util.ArrayList<>();
        fileIdList.add(encryptedFileId);

        for(String keyword : keywords){
            String searchToken = generateDeterministicToken(keyword);
            searchIndex.put(searchToken, fileIdList);
        }
        return searchIndex;
    }
    public String generateDeterministicToken(String keyword) throws Exception {
    // Usamos HMAC-SHA256 como uma PRF Determinística, chaveada pela seKey
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(this.seKey);
    
    byte[] keywordBytes = keyword.getBytes(StandardCharsets.UTF_8);
    byte[] token = mac.doFinal(keywordBytes);
    
    // Converte o token binário para Base64 para ser usado como chave String no Map
    return Base64.getEncoder().encodeToString(token); 
    }
    private byte[] encryptConfidential(byte[] plaintext) throws Exception {
    // Reutiliza a lógica robusta de AEAD (usando AES/GCM)
    
    // 1. Gera IV/Nonce
    byte[] iv = new byte[GCM_IV_LENGTH];
    secureRandom.nextBytes(iv);
    
    // 2. Criptografa e Autentica
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
    
    // Usa a chave de ENCRIPTAÇÃO principal (sKey)
    cipher.init(Cipher.ENCRYPT_MODE, sKey, gcmSpec);
    
    byte[] cipherText = cipher.doFinal(plaintext);

    // 3. Combina IV e Ciphertext + Tag para o bloco final
    ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
    byteBuffer.put(iv);
    byteBuffer.put(cipherText);
    
    return byteBuffer.array();
}
    public byte[] decryptConfidential(byte[] cipherBlock) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(cipherBlock);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, sKey, gcmSpec);
        return cipher.doFinal(cipherText);
    }


    /* 
    private String encryptString (String plaintext, SecretKeySpec kek) throws Exception{
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek.getEncoded(),"AES"), gcmSpec);
        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(byteBuffer.array());
    }
    private String decryptString (String ciphertext, SecretKeySpec kek) throws Exception{
        byte[] decodedData = Base64.getUrlDecoder().decode(ciphertext);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decodedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek.getEncoded(),"AES"), gcmSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }
    */

    public static void main(String[] args) {
    try {
        // Password used for key encryption/decryption
        char[] password = "StrongPass123!".toCharArray();

        // Create CryptoManager for client ID "1904"
        CryptoManager cm = new CryptoManager(password, "1904");

        // ---- Test Key Loading ----
        System.out.println("\n[TEST] Loading keys from KeyStore...");
        cm.loadKeys();  // This should print success messages for enc/hmac keys

        // ---- Test Encryption ----
        String message = "Hello from the CryptoManager!";
        System.out.println("[TEST] Encrypting message: " + message);
        byte[] encrypted = cm.encryptBlock(message.getBytes(StandardCharsets.UTF_8));

        if (encrypted != null) {
            System.out.println("[RESULT] Ciphertext (Base64): " + Base64.getEncoder().encodeToString(encrypted));
        } else {
            System.err.println("[ERROR] Encryption failed!");
        }

    } catch (Exception e) {
        e.printStackTrace();
    }
}

}
