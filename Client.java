import java.io.*;
import java.net.InetAddress;
import java.net.Socket;

public class Client
{
    String host;
    int port;

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


    public static void main(String args[])
    {
        try
        {
            Client client = new Client();
            client.sendMessage("test");

            String returnMessage = client.getMessage();
            System.out.println("Message received from the server: " +returnMessage);

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
