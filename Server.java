import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import javax.crypto.KeyGenerator; 
import javax.crypto.Cipher;
import java.util.Base64;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.PrintStream;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;



public class Server
{

    static final String ALGORITHM = "RSA";
    static final int CONFIDENTIALITY = 4;
    static final int INTEGRITY = 2;
    static final int AUTHENTICATION = 1;

    static boolean confidentiality;
    static boolean authenticaiton; 
    static boolean integrity; 

    static int optionsSelected;
    static SecretKey sessionKey; 

    static PublicKey serverPublicKey;
    static PrivateKey privateKey;
    static PublicKey publicKeyClient;

    static KeyPair keyPair;   

    int port;
    static ServerSocket serverSocket;

    static final byte[] key = new byte[] {'!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r'};


    private static Socket socket;


    public Server() throws java.io.IOException{
        port = 8080;
        serverSocket = new ServerSocket(port);
        System.out.println("Server Started and listening to the port 8080");
    }

    public String checkInput() throws java.io.IOException{
        Scanner scanner = new Scanner(socket.getInputStream());
        String message = scanner.nextLine();

        return message;
    }

    public void sendOutput(String message) throws java.io.IOException{
        OutputStream os = socket.getOutputStream();
        OutputStreamWriter osw = new OutputStreamWriter(os);
        BufferedWriter bw = new BufferedWriter(osw);
       
        bw.write(message);
        bw.flush();
    }

    private static void optionsSelected(){
        int temp = optionsSelected;

        if(optionsSelected > 3){
            confidentiality = true;
            temp = optionsSelected - 4;
        }else{
            confidentiality = false;
        }if(temp > 1){
            integrity = true;
            temp = temp - 2;
        }else{
            integrity = false; 
        }
        if(temp == 1){
            authenticaiton = true;
        }else{
            authenticaiton = false; 
        }
    }

    private static int getSecurity(){
        Scanner scan = new Scanner(System.in);
        boolean input = false; 

        int option = 0;
        int val = 0;

        for(int i = 0; i < 3; i++){
            input = false;
            if(i == 0){
                System.out.println("Would you like Confidentiality? (y/n)");
                val = CONFIDENTIALITY;
            }
            else if(i == 1){
                System.out.println("Would you like Integrity? (y/n)");
                val = INTEGRITY;
            }
            else if(i == 2){
                System.out.println("Would you like Authentication? (y/n)");
                val = AUTHENTICATION;
            } 
            else{

            }
            while(!input){
                char selection = scan.next().charAt(0);
                if(selection == 'y'){
                    option += val; 
                    input = true;
                }else if(selection == 'n'){
                    input = true; 
                }else{
                    System.out.println("Please enter a valid option");
                }

            }
        }
        return option;
    }

    public static byte[] encrypt(byte[] publicKey, byte[] inputData) throws Exception {

        PublicKey key = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.PUBLIC_KEY, key);

        byte[] encryptedBytes = cipher.doFinal(inputData);

        return encryptedBytes;
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        // 512 is keysize
        keyGen.initialize(512, random);

        KeyPair generateKeyPair = keyGen.generateKeyPair();
        return generateKeyPair;
    }
    public static String encrypt(String data, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encVal);
        return encryptedValue;
    }
    public static String decrypt(String encryptedData, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES");

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue =  Base64.getDecoder().decode(encryptedData.getBytes());
        byte[] decryptedVal = c.doFinal(decodedValue);

        return new String(decryptedVal, "UTF-8");
    }

    private static String generateMAC(String msg) throws Exception {
    // create a MAC and initialize with the key
        Mac mac  = Mac.getInstance("HmacSHA256");
        mac.init(sessionKey);

        byte[] b = msg.getBytes("UTF-8");
        byte[] result = mac.doFinal(b);

        return new String(result);

    }

    private static SecretKey generateSessionKey(byte[] key) throws Exception{
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
       
        SecretKey skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }

    private static SecretKey generateSessionKey() throws Exception{
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); 
        // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
        byte[] key = keygen.generateKey().getEncoded();
       
        SecretKey skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }
    private static String hashPw(String pw){
        MessageDigest messageDigest;
        String digested = "";
        try{
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(pw.getBytes());
            digested =  bytesToHex((messageDigest.digest()));
            System.out.println(pw +" hash to: "+digested);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return digested;
    }
        private static boolean compare(String un,String pw){


        File file = new File("account.txt");
        boolean found = false;
        try{
            Scanner fileScanner = new Scanner(file);

            while(fileScanner.hasNextLine())
           {
                String username = fileScanner.nextLine();
                if(username.equals(un)){
                    String password = fileScanner.nextLine();
                    if(password.equals(hashPw(pw))){
                        found = true;
                    }
                }
            }
        }
        catch(FileNotFoundException e){
            e.printStackTrace();
        }

        return found;
        
    }
    private static final char[] hexDigit = "0123456789abcdef".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; ++i) {
            int b = bytes[i] & 0xFF;
            hexChars[i * 2] = hexDigit[b >>> 4];
            hexChars[i * 2 + 1] = hexDigit[b & 0x0F];
        }
    return new String(hexChars);
}
 public static PublicKey LoadPublicKey()
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        String algorithm = "RSA";
        // Read Public Key.
        File filePublicKey = new File( "cpublic.key");
        FileInputStream fis = new FileInputStream( "cpublic.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();
 
        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }
    public static void main(String[] args)
    {
        boolean first = true;
        try
        {
            String message;
            String sendingMessage;

            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            Server server = new Server();
            optionsSelected = getSecurity();

            optionsSelected();
            while(true){
            
            socket = serverSocket.accept();

            String clientOptionsSelected = null;
            while(clientOptionsSelected == null){
                clientOptionsSelected = server.checkInput();
            }

            if(clientOptionsSelected.equals(String.valueOf(optionsSelected))){
                server.sendOutput("security protocols accepted \n");

                if(confidentiality || integrity){
                    //ObjectInputStream objIn = new ObjectInputStream(server.socket.getInputStream());
                    publicKeyClient = LoadPublicKey();

                    //generate a session key
                    sessionKey = generateSessionKey();

                    //encrypt the session key with server's public key
                    byte[] encryptedSessionKey = encrypt(publicKeyClient.getEncoded(), sessionKey.getEncoded());

                    //send the encrypted session key to the server
                    ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
                    objOut.writeObject(encryptedSessionKey);
                }
                if(authenticaiton){
                    while(true){
                        Scanner reader = new Scanner(System.in);  // Reading from System.in
                        System.out.println("Enter a username: ");
                        String username = reader.nextLine(); // Scans the next line of the input as an string.
                        System.out.println("Enter a password: ");
                        String password = reader.nextLine(); // Scans the next token of the input as an int.
                        if(compare(username,password) == true){
                            System.out.println("sign in as "+ username);
                            break;
                        }else{
                            System.out.println("invalid username/password input agian");
                        }
                    }
                }

                while(true){
                    //User input
                    if(input.ready()){
                        sendingMessage = input.readLine();   
                        if(confidentiality){
                            // send the encrypted input 
                            server.sendOutput(server.encrypt(sendingMessage, sessionKey) +"\n");
                        }if(integrity){
                            //generate MAC
                            String mac = server.generateMAC(sendingMessage);
                            if(!confidentiality){
                                //Send unencrypted message
                                server.sendOutput(sendingMessage + "\n");
                            }
                            //send the mac
                            server.sendOutput(mac +"\n");
                        }
                        else if(!confidentiality && !integrity) {
                            server.sendOutput(sendingMessage +"\n");
                        }
                    }  

                    BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    if(br.ready()){
                        message = br.readLine();
                        if(integrity){
                            if(confidentiality){
                                message = decrypt(message, sessionKey);
                            }
                            String mac = server.generateMAC(message);
                            
                            String sentMac = br.readLine();
                            while(br.ready()){
                                sentMac += "\n";
                                sentMac += br.readLine();

                            }
                            if(mac.equals(sentMac)){
                                System.out.println(message);
                            }else{
                                System.out.println("message is altered");
                            }
                        }else if(confidentiality){
                                System.out.println(decrypt(message, sessionKey));
                        }
                    
                        else if(!integrity && !confidentiality){
                            System.out.println(message);
                        }
                    }                 
                }

            }else{
                System.out.println("ERROR: Server and Client security settings must be the same \n");
                server.sendOutput("security protocols declined \n");

                socket.close();
            }

           }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            try
            {
                socket.close();
            }
            catch(Exception e){}
        }
    }
}