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


public class Server
{

    static final int CONFIDENTIALITY = 4;
    static final int INTEGRITY = 2;
    static final int AUTHENTICATION = 1;

    static boolean confidentiality;
    static boolean authenticaiton; 
    static boolean integrity; 

    static int optionsSelected;
    static SecretKey sessionKey; 

    static PublicKey publicKeyServer;
    static PrivateKey privateKey;
    static PublicKey publicKeyClient;   

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


    public static String encrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, publicKeyServer);
        byte[] encVal = c.doFinal(data);
        String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encVal);
        return encryptedValue;
    }

    public static String decrypt(String encryptedData) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        c.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedValue =  Base64.getDecoder().decode(encryptedData.getBytes());
        byte[] decryptedVal = c.doFinal(decodedValue);

        return new String(decryptedVal, "UTF-8");
    }
    public static String encrypt(String data, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encVal);
        return encryptedValue;
    }
    public static String decrypt(String encryptedData, Key key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue =  Base64.getDecoder().decode(encryptedData.getBytes());
        byte[] decryptedVal = c.doFinal(decodedValue);

        return new String(decryptedVal, "UTF-8");
    }

    private static String userInput(Scanner input){
        String sendingMessage;
        if(input.hasNext()){
            sendingMessage = input.nextLine();
            return sendingMessage;
        }
        return null;
    }
    private static String generateMAC(String msg) throws Exception {
    // create a MAC and initialize with the key
        Mac mac  = Mac.getInstance("HmacSHA256");
        mac.init(sessionKey);

        byte[] b = msg.getBytes("UTF-8");
        byte[] result = mac.doFinal(b);

        return new String(result);


    }

    public static void genKeys() throws Exception{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);
        KeyPair keypair = keyGen.genKeyPair();
        privateKey = keypair.getPrivate();
        publicKeyServer = keypair.getPublic();
    }


    private static SecretKey generateSessionKey(byte[] key) throws Exception{
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
       
        SecretKey skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
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
                    /* Receive the session key from the client... needs fix */

                    //generate servers public/private keys
                    genKeys();
                    
                    ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
                    objOut.writeObject(publicKeyServer);


                    ObjectInputStream objIn = new ObjectInputStream(socket.getInputStream());
                    String encryptedSessionKey = (String) objIn.readObject();
                    System.out.println("ENCRYPTED SESSION KEY: "+encryptedSessionKey);

                    //decrypt the session key with private key
                    String decryptedSessionKey = decrypt(encryptedSessionKey);
                    System.out.println("DECRYPTED SESSION KEY: "+decryptedSessionKey);

                    //generate the session key between client and server
                    sessionKey = generateSessionKey(decryptedSessionKey.getBytes());
                    System.out.println(new String(sessionKey.getEncoded()));
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
