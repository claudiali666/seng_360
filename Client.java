import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;
import java.util.Base64;
import javax.crypto.KeyGenerator; 
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;




public class Client
{
    static final int CONFIDENTIALITY = 4;
    static final int INTEGRITY = 2;
    static final int AUTHENTICATION = 1;

    static boolean confidentiality;
    static boolean authenticaiton; 
    static boolean integrity; 

    static Scanner scanner;
    static int optionsSelected;

    static KeyPair keyPair;
    static PublicKey serverPublicKey;
    static PublicKey publicKeyClient;
    static PrivateKey privateKey;

    static SecretKey sessionKey;


    String host;
    int port;


    static final byte[] publicKey = new byte[] {'!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r'};

    private static Socket socket;

    public Client() throws IOException {
        port = 8080;
        socket = new Socket("127.0.0.1", port);
    }

    public void sendMessage(String message) throws IOException {
        //Send the message to the server
        OutputStream os = socket.getOutputStream();
        OutputStreamWriter osw = new OutputStreamWriter(os);
        BufferedWriter bw = new BufferedWriter(osw);

        bw.write(message);
        bw.flush();
    }

    public String getMessage() throws IOException {
        InputStream is = socket.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        String message = br.readLine();
        return message;
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

    private static SecretKey generateSessionKey() throws Exception{
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
        byte[] key = keygen.generateKey().getEncoded();
       
        SecretKey skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }


   public static String encrypt(byte[] data) throws Exception {
        //Key key = generateKey();

        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encVal = c.doFinal(data);
        String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encVal);

        return encryptedValue;
    }



    public static String decrypt(String encryptedData) throws Exception {
        //Key key = generateKey();
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
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
        //Key key = generateKey();
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
        publicKeyClient = keypair.getPublic();
    }

    private static PublicKey recievePubicKey() {
        File pk = new File("public_key.ser");
        while (pk.length() == 0) {
            // here we just wait
        }
        System.out.println("File Found...");
        try {
            FileInputStream f_in = new FileInputStream("public_key.ser");
            ObjectInputStream obj_in = new ObjectInputStream(f_in);
            PublicKey publicKey_Client = (PublicKey) obj_in.readObject();
            obj_in.close();
            pk.delete();
            return publicKey_Client;
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Error: IOException...");
            return null;
        } catch (ClassNotFoundException e) {
            System.out.println("Error: Class not found exception...");
            return null;
        }
     }

    public static void main(String args[])
    {
        try
        {
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

            String message;
            String sendingMessage;

            Client client = new Client();
            optionsSelected = getSecurity();
            optionsSelected();

            client.sendMessage(Integer.toString(optionsSelected) +"\n");
            message = client.getMessage();
            System.out.println(message);

            if(confidentiality || integrity){
                /* Sending the session key to the server.. needs fix */ 
                //receive the server's public key
                //serverPublicKey = recievePubicKey();
                ObjectInputStream objIn = new ObjectInputStream(client.socket.getInputStream());
                serverPublicKey = (PublicKey) objIn.readObject();

                //generate a session key
                sessionKey = generateSessionKey();

                //encrypt the session key with server's public key
                String encryptedSessionKey = encrypt(sessionKey.getEncoded());
                System.out.println("DECRYPTED SESSION KEY: "+sessionKey.getEncoded());
                System.out.println("ENCRYPTED SESSION KEY: "+encryptedSessionKey);

                //send the encrypted session key to the server
                ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
                objOut.writeObject(encryptedSessionKey);
                objOut.close();

            
            }
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            while(true){
                
                if(input.ready()){
                    sendingMessage = input.readLine();   
                    if(confidentiality){
                        client.sendMessage(client.encrypt(sendingMessage, sessionKey) +"\n");
                    }if(integrity){
                        String mac = generateMAC(sendingMessage);
                        if(!confidentiality){
                            client.sendMessage(sendingMessage + "\n");
                        }
                        client.sendMessage(mac +"\n");
                    }
                    else if(!integrity && !confidentiality){
                        client.sendMessage(sendingMessage +"\n");
                    }
                }  

                if(br.ready()){
                    message = br.readLine();
                    if(integrity){
                        if(confidentiality){
                            message = decrypt(message);

                        }
                        String mac = generateMAC(message);
                        String sentMac = br.readLine();
                        while(br.ready()){
                            sentMac += "\n";
                            sentMac += br.readLine();

                        }                        
                        if(mac.equals(sentMac)){
                            System.out.println(message);
                        }
                    }
                    else if(confidentiality){
                        System.out.println(decrypt(message));
                    }

                
                    else if(!integrity && !confidentiality){
                        System.out.println(message);
                    }
                }

            }

        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }
        finally
        {
            try
            {
                socket.close();
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }
        }
    }
}
