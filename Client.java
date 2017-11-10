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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;





public class Client
{
    static final String ALGORITHM = "RSA";
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
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); 
        // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
        byte[] key = keygen.generateKey().getEncoded();
       
        SecretKey skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }

    public static byte[] decrypt(byte[] privateKey, byte[] inputData) throws Exception {

        PrivateKey key = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.PRIVATE_KEY, key);
        byte[] decryptedBytes = cipher.doFinal(inputData);

        return decryptedBytes;
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
        //Key key = generateKey();
        mac.init(sessionKey);

        byte[] b = msg.getBytes("UTF-8");

        byte[] result = mac.doFinal(b);

        return new String(result);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        // 512 is keysize
        keyGen.initialize(512, random);

        KeyPair generateKeyPair = keyGen.generateKeyPair();
        return generateKeyPair;
    }
     private static SecretKey generateSessionKey(byte[] key) throws Exception{
        KeyGenerator keygen = KeyGenerator.getInstance("AES"); // key generator to be used with AES algorithm.
        keygen.init(256); // Key size is specified here.
       
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
    public static PrivateKey LoadPrivateKey()
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Private Key.
        File filePrivateKey = new File( "cprivate.key");
        FileInputStream fis = new FileInputStream("cprivate.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();
 
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
 
        return privateKey;
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
                    //generate servers public/private keys
                   
                    privateKey = LoadPrivateKey();
                    //publicKeyClient = keyPair.getPublic();
                    
                    // ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
                    // objOut.writeObject(publicKeyClient);

                    ObjectInputStream objIn = new ObjectInputStream(socket.getInputStream());
                    byte[] encryptedSessionKey = (byte[]) objIn.readObject();

                    //decrypt the session key with private key
                    byte[] decryptedSessionKey = decrypt(privateKey.getEncoded(), encryptedSessionKey);

                    //generate the session key between client and server
                    sessionKey = generateSessionKey(decryptedSessionKey);
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
                            message = decrypt(message, sessionKey);

                        }
                        String mac = generateMAC(message);
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
                    }
                    else if(confidentiality){
                        System.out.println(decrypt(message, sessionKey));
                    }

                
                    else if(!integrity && !confidentiality){
                        System.out.println(message);
                    }
                }

            }

        }
        catch (Exception exception)
        {
            //exception.printStackTrace();
            System.out.println("ERROR: Connection Declined");
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