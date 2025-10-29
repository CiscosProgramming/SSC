import java.io.File;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets; // Para codificação/decodificação Base64
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;     // Para geração segura de números aleatórios (essencial para KeyGenerator)
import java.util.Base64;               // Para codificar a chave em Base64 antes de guardar
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

    private final String KEY_DIR = "Java/client/KeyStore/"; //Diretoria para guardar a chave
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    
    //Criar palavra passe para gerar uma master key que desencripta as outras keys em KeyStore
    // A palavra passe e fornecida pelo utilizador na inicialização do cliente
    // tera que ser sempre a mesma caso contrario a master key calculada sera diferente e as keys nao poderao ser desencriptadas

    public CryptoManager(char[] pwd, String clienteId){
        this.clienteId = clienteId;
        this.pwd = pwd;
        secureRandom = new SecureRandom();
        try {
            loadFile();
            File keyFile = new File(KEY_DIR + this.clienteId + "_enc.key");//Verificar se a key ja existe
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
        File crypto = new File("Java/client/cryptoconfig.txt");
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
            case "AES/GCM":
                //Generate AES key
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(key,secureRandom);
                sKey = kg.generateKey();
                System.out.println("Generated AES key of size " + key + " bits.");
                break;
            case "AES/CBC/PKCS5Padding":
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
            case "CHACHA20-Poly1305":
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
        String KeyFileEnc = KEY_DIR + this.clienteId + "_enc.key"; 
        String KeyFileAuth = KEY_DIR + this.clienteId + "_auth.key";
        try{
            //Gerar salt
            byte[] salt = new byte[SALT_LENGTH];
            secureRandom.nextBytes(salt);
            //KEK
            SecretKey kek = getMKey(salt);
            //Guardar chave de encriptação
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            byte[] encryptedData = encryptMasterKey(sKey, kek, iv);
            protectKey(salt, encryptedData, KeyFileEnc);
            System.out.println("Encryption key stored successfully in " + KeyFileEnc);
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
                if(f.getName().endsWith("_enc.key")){
                    sKey = originalKey;
                    System.out.println("Encryption key loaded successfully from " + f.getName());
                }else if(f.getName().endsWith("_auth.key")){
                    hmac = originalKey;
                    hasHmac = true;
                    System.out.println("HMAC key loaded successfully from " + f.getName());
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
                loadKeys();// Load the keys and decrypt them so that we can now encrypt data with them
                switch(algorithm){
                    case "AES/GCM":
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
                    case "AES/CBC/PKCS5Padding":
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
                    case "CHACHA20-Poly1305":
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


    //decryptBlock

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
