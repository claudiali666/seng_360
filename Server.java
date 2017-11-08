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
public class Server
{
    static final int CONFIDENTIALITY = 4;
    static final int INTEGRITY = 2;
    static final int AUTHENTICATION = 1;

    static boolean confidentiality;
    static boolean authenticaiton; 
    static boolean integrity; 

    static int optionsSelected;

    int port;
    ServerSocket serverSocket;

    static final byte[] key = new byte[] {'!', '-', 't', 'r'};


    private static Socket socket;

    public Server() throws java.io.IOException{
        port = 8080;
        serverSocket = new ServerSocket(port);
        System.out.println("Server Started and listening to the port 8080");
    }

    public String checkInput() throws java.io.IOException{
        socket = serverSocket.accept();
        InputStream is = socket.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        String message = br.readLine();
        return message;
    }

    public void sendOutput(String message) throws java.io.IOException{
        OutputStream os = socket.getOutputStream();
        OutputStreamWriter osw = new OutputStreamWriter(os);
        BufferedWriter bw = new BufferedWriter(osw);
       
        bw.write(message);
        System.out.println("Sending message: "+message);
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
    //Confidentiality - need to encrypt the messages sent over the network from the server and the client, symmetrically 
    //and can assume that the public keys are already known 

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

    //Integrity - need to ensure that the messages sent to and from the server are the same on both sides 
    private static byte[] generateMAC(String msg) throws Exception {
        // create a MAC and initialize with the key
        Mac mac  = Mac.getInstance("HmacSHA256");
        SecretKeySpec key = generateKey();
        mac.init(key);

        byte[] b = msg.getBytes("UTF-8");

        byte[] result = mac.doFinal(b);

        return result;


    }
    //Authenticaiton - need to ensure the identities of the client and server by using a username and password possibly 



    public static void main(String[] args)
    {
        try
        {
            Server server = new Server();
            optionsSelected = getSecurity();

            optionsSelected();
            System.out.println("Confidentiality: "+confidentiality );
            System.out.println("Integrity: "+integrity);
            System.out.println("Authentication: "+authenticaiton);


            while(true)
            {
                String message = server.checkInput();
                System.out.println(message);


                if(Integer.valueOf(message) == optionsSelected){
                    System.out.println("Same security options have been selected"); 
                }else{
                    System.out.println("ERROR: Different security options have been selected"); 

                }
                message = server.checkInput();
                System.out.println(decrypt(message));


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
