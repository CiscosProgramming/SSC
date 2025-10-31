import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets; // Para codificação/decodificação Base64
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;     // Para geração segura de números aleatórios (essencial para KeyGenerator)
import java.util.Base64;               // Para codificar a chave em Base64 antes de guardar
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator; //Gerar key
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey; //Representar chave secreta


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
    private final String KEY_DIR = "KeyStore/"; //Diretoria para guardar a chave
    private SecretKey seKey;

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
    private void storeKey(){
        String keystore = KEY_DIR + this.clienteId + ".jceks";
        try{
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(null, this.pwd);
            KeyStore.ProtectionParameter pparam = new KeyStore.PasswordProtection(pwd);
            
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(sKey);
            ks.setEntry("enc_key", skEntry, pparam);

            if(this.seKey != null){
                KeyStore.SecretKeyEntry seEntry = new KeyStore.SecretKeyEntry(seKey);
                ks.setEntry("se_key", seEntry, pparam);
            }

            if(hasHmac && hmac != null){
                KeyStore.SecretKeyEntry hmacEntry = new KeyStore.SecretKeyEntry(hmac);
                ks.setEntry("auth_key", hmacEntry, pparam);
            }
            
            try(FileOutputStream fos = new FileOutputStream(keystore)){
                ks.store(fos, pwd);
            }
            System.out.println("Keys stored successfully in client Keystore " + clienteId);
        }catch(Exception e){
            System.err.println("Error storing keys in client Keystore");
        }
    }
    private void loadKeys(){
        if (sKey != null && (!hasHmac || (hasHmac && hmac != null))) {
        return;
        }
        String keystore = KEY_DIR + this.clienteId + ".jceks";
        File ksFile = new File(keystore);

        if(!ksFile.exists()){
            System.err.println("[ERROR] Keystore file not found: " + keystore);
            return;
        }

        try{
            KeyStore ks = KeyStore.getInstance("JCEKS");
            try(FileInputStream fis = new FileInputStream(ksFile)){
                ks.load(fis, this.pwd);
            }
            KeyStore.ProtectionParameter pparam = new KeyStore.PasswordProtection(pwd);
            
            KeyStore.SecretKeyEntry encEntry = (KeyStore.SecretKeyEntry) ks.getEntry("enc_key", pparam);
            if(encEntry != null){
                sKey = encEntry.getSecretKey();
                System.out.println("Encryption key loaded successfully from client Keystore.");
            }

            KeyStore.SecretKeyEntry seEntry = (KeyStore.SecretKeyEntry) ks.getEntry("se_key", pparam);
            if(seEntry != null){
                seKey = seEntry.getSecretKey();
                System.out.println("Searchable Encryption key loaded successfully from client Keystore.");
            }

            KeyStore.SecretKeyEntry hmacEntry = (KeyStore.SecretKeyEntry) ks.getEntry("auth_key", pparam);
            if(hmacEntry != null){
                hmac = hmacEntry.getSecretKey();
                hasHmac = true;
                System.out.println("HMAC key loaded successfully from client Keystore.");
            }


        }catch(java.io.IOException e){
            if(e.getCause() instanceof javax.crypto.BadPaddingException){
                System.err.println("[ERROR] Invalid password for Keystore decryption.");
            }else{
                System.err.println("Error loading keys from client Keystore: " + e.getMessage());
            }
        }catch(Exception e){
                System.err.println("Error reading JCEKS keystore"); // Debug
            }
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
}
