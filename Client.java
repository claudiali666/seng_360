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


    String host;
    int port;


    static final byte[] key = new byte[] {'!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r','!', '-', 't', 'r'};


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

    private static Key generateKey() throws Exception{
       
        Key skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }

   public static String encrypt(String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encVal);
        return encryptedValue;
    }

    public static String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    private static String userInput(Scanner input){
        String sendingMessage;
        if(input.hasNext()){
            sendingMessage = input.nextLine();
            return sendingMessage;
        }
        return null;
    }

     private static byte[] generateMAC(String msg) throws Exception {
    // create a MAC and initialize with the key
        Mac mac  = Mac.getInstance("HmacSHA256");
        Key key = generateKey();
        mac.init(key);

        byte[] b = msg.getBytes("UTF-8");

        byte[] result = mac.doFinal(b);

        return result;


    }


    public static void main(String args[])
    {
        try
        {
            Scanner input = new Scanner(System.in);
            String message;
            String sendingMessage;

            Client client = new Client();
            optionsSelected = getSecurity();
            optionsSelected();

            client.sendMessage(Integer.toString(optionsSelected) +"\n");
            message = client.getMessage();
            System.out.println(message);

            while(true){
                message = client.getMessage();
                if(message != null){
                    if(confidentiality){
                        System.out.println(decrypt(message));
                    }else{
                        System.out.println(message);
                    }
                } 
                if(input.hasNext()){
                    sendingMessage = input.nextLine();
                    if(confidentiality){
                        client.sendMessage(encrypt(sendingMessage) +"\n");
                    }else{
                        client.sendMessage(sendingMessage +"\n");
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
