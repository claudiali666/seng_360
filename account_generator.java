import java.io.*;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class account_generator{
	public static void main(String[] args){
		while(true){
			Scanner reader = new Scanner(System.in);  // Reading from System.in
			System.out.println("Enter a username: ");
			String username = reader.nextLine(); // Scans the next line of the input as an string.
			System.out.println("Enter a password: ");
			String password = reader.nextLine(); // Scans the next token of the input as an int.
			// if(compare(username,password) == true){
			// 	System.out.println("sign in as "+ username);
			// 	break;
			// }else{
			// 	System.out.println("invalid username/password input agian";
			// }
			//hash password
			String hashedPw = hashPw(password);
			//store account info to local directory
			try (Writer writer = new BufferedWriter(new OutputStreamWriter(
             	new FileOutputStream("account.txt", true), "utf-8"))) {
   				writer.write(username + "\n" +hashedPw + "\n");
			}catch(IOException e){
				e.printStackTrace();
			}

		}

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
	            	System.out.println("in the file: "+password);
	            	if(password.equals(hashPw(pw))){
	            		//sign in as un
	            		System.out.println("sign in!");
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
}