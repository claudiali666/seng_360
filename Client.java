import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;
import java.util.Base64;
import javax.crypto.KeyGenerator; 
import javax.crypto.Cipher;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;


public class Client
{
    static final int CONFIDENTIALITY = 4;
    static final int INTEGRITY = 2;
    static final int AUTHENTICATION = 1;


    String host;
    int port;

    static final byte[] key = new byte[] {'!', '-', 't', 'r'};


    private static Socket socket;

    public Client() throws IOException {
        host = "localhost";
        port = 8080;
        InetAddress address = InetAddress.getByName(host);
        socket = new Socket(address, port);
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
        //Get the return message from the server
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

    private static SecretKeySpec generateKey() throws Exception{
       
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        return skeySpec;
    }

    private static String encrypt(String data) throws Exception{
        SecretKeySpec key = generateKey();
        Cipher c = Cipher.getInstance("AES");

        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encodedValue = c.doFinal(data.getBytes());
        String encryptedValue = Base64.getEncoder().encodeToString(encodedValue);

        return encryptedValue;
    }

    private static String decrypt(String data) throws Exception {
        SecretKeySpec key = generateKey();
        Cipher c = Cipher.getInstance("AES");

        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decoderVal = Base64.getDecoder().decode(data);
        byte[] decryptedValue = c.doFinal(decoderVal);

        data = new String(decryptedValue);

        return data;


    }

    private static byte[] generateMAC(String msg) throws Exception {
        // create a MAC and initialize with the key
        Mac mac  = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = generateKey();
        mac.init(key);

        byte[] b = msg.getBytes("UTF-8");

        byte[] result = mac.doFinal(b);

        return result;


    }


    public static void main(String args[])
    {
        try
        {
            Client client = new Client();
            int securityOptions = getSecurity();

            client.sendMessage(Integer.toString(securityOptions));

            client.sendMessage(encrypt("this is a test"));



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
