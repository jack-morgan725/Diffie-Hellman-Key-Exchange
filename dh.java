
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;    
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.Charset;

/**
* Diffie-Hellman class completes a Diffie-Hellman key exchange, decrypts a message received by the server, encrypts
* this message, and then returns it to the server for verification. 
* 
* @author Jack Morgan
* @version 1.0
* @since 2019-02-12
* 
* Client commands: 
* Command P2.1: java -jar dh.jar 127.0.0.1 8050 53 27 15
* Command P2.2: java -jar dh.jar 127.0.0.1 8050 9976 3 34
* Command P2.3: java -jar dh.jar 127.0.0.1 8050 3769 1794 87
* Command P2.4: java -jar dh.jar 127.0.0.1 8050 15073 9179 8239
* Command P2.5: java -jar dh.jar 127.0.0.1 8050 100169 90185 82447 
* Command P2.6: java -jar dh.jar 127.0.0.1 8050 10406729 123492 118877
*
* Server commands: 
* Command P2.1: java -jar diffeehellmanserver.jar 8050 53 27 11 test.txt
* Command P2.1: java -jar diffeehellmanserver.jar 8050 9976 3 34 test.txt
* Command P2.1: java -jar diffeehellmanserver.jar 8050 3769 1794 87 test.txt
* Command P2.1: java -jar diffeehellmanserver.jar 8050 15073 9179 8239 test.txt
* Command P2.1: java -jar diffeehellmanserver.jar 8050 100169 90185 82447 test.txt
* Command P2.1: java -jar diffeehellmanserver.jar 8050 10406729 123492 118877 test.txt
*
* Command P2.2: java -jar diffeehellmanserver.jar 8050 53 27 11 creditcard.txt
* Command P2.2: java -jar diffeehellmanserver.jar 8050 9976 3 34 creditcard.txt
* Command P2.2: java -jar diffeehellmanserver.jar 8050 3769 1794 87 creditcard.txt
* Command P2.2: java -jar diffeehellmanserver.jar 8050 15073 9179 8239 creditcard.txt
* Command P2.2: java -jar diffeehellmanserver.jar 8050 100169 90185 82447 creditcard.txt
* Command P2.2: java -jar diffeehellmanserver.jar 8050 10406729 123492 118877 creditcard.txt
*
* Command P2.3: java -jar diffeehellmanserver.jar 8050 53 27 11 hobbit.txt
* Command P2.3: java -jar diffeehellmanserver.jar 8050 9976 3 34 hobbit.txt
* Command P2.3: java -jar diffeehellmanserver.jar 8050 3769 1794 87 hobbit.txt
* Command P2.3: java -jar diffeehellmanserver.jar 8050 15073 9179 8239 hobbit.txt
* Command P2.3: java -jar diffeehellmanserver.jar 8050 100169 90185 82447 hobbit.txt
* Command P2.3: java -jar diffeehellmanserver.jar 8050 10406729 123492 118877 hobbit.txt
*/
public class dh 
{
	/**
	* Accepts a set of string arguments from the terminal, assigns the provided input, and calls the method
	* associated with the mode selected by the user.
	* @param args[0] serverIP the IP address of the Diffie-Hellman server.
	* @param args[1] serverPort the PORT used to connect to the Diffie-Hellman server.
	* @param args[2] modValue the prime value used to compute the shared key. 
	* @param args[3] base the generator value used to compute the shared key.
	* @param args[4] clientSecret the clients secret value.
	*/
	public static void main(String args[]) 
	{
		if (args.length < 5) 
		{
			System.out.println("Not enough arguments entered.");
			return;
		}

		String ipServerAddress = args[0];
		String serverPort = args[1];
		String modValue = args[2];
		String genValue = args[3];
		String clientSecret = args[4];
		
		try 
		{	
			//--> Connect to server.
			InetAddress serverAddress = InetAddress.getByName(ipServerAddress); 
			Socket socket = new Socket(serverAddress, Integer.parseInt(serverPort));
			
			//--> Create a BufferedReader to accept input from the socket (server).
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		
			//--> Create a PrintWriter to write to the socket (server).
			PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
			
			BigInteger generator = new BigInteger(genValue);	
			BigInteger primeValue = new BigInteger(modValue); 
			BigInteger aliceSecret = new BigInteger(clientSecret);
	
			//--> Calculate A and send it to the server.
			BigInteger alice = generator.pow(aliceSecret.intValue()).mod(primeValue);
			String clientMessage = "**DHA**"+alice+"****";
			out.println(clientMessage); 
			
			//--> Retrieve server response and calculate the shared key.
			String serverStringResponse = in.readLine();

			BigInteger serverResponse = new BigInteger((serverStringResponse.substring(7)).substring(0, (serverStringResponse.substring(7)).indexOf("*")));	  
			BigInteger sharedKey = serverResponse.pow(aliceSecret.intValue()).mod(primeValue);
			
			//--> Generate the base key by concatenating a random 4-character String with the padded 12-byte key.
			String randomString = dh.generateNonseString();
			String paddedKey = dh.padKey(sharedKey.toString());
			String concatenatedKey = randomString + paddedKey;
			
			byte[] sessionKey = hashUsingMD5(concatenatedKey);
			
			//--> Send the random 4-character String to the server.
			out.println("**NONCE**"+randomString+"****");
			
			//--> Request encrypted file.
			out.println("**REQ****");
			String encryptedMessage = in.readLine();
			encryptedMessage = (encryptedMessage.substring(7)).substring(0, encryptedMessage.substring(7).indexOf('*'));
			
			//--> Decode and decrypt the received message. 
			String decryptedMessage = dh.decodeAndDecrypt(encryptedMessage, concatenatedKey, sessionKey);
			
			//--> Encode and encrypt the decrypted message and return it to the server for verification.
			String encryptedMessageForServer = "**VERIFY**"+dh.encodeAndEncrypt(decryptedMessage, concatenatedKey, sessionKey)+"****";
			
			out.println(encryptedMessageForServer); 
			System.out.println("Verification Status: "+ in.readLine());
			socket.close();
		} 
		catch (IOException e) 
		{
			System.err.println("Invalid filename enterered.");
		}
	}
	
	/**
	* Generates a random 4-character String consisting of the characters a-z.
	* @return randomString a random 4-character String consisting of the characters a-z.
	*/
	public static String generateNonseString() 
	{
		String randomString = "";
		Random randomValueGen = new Random();
			
		for (int i = 0; i < 4; i++) 
			randomString += (char)(randomValueGen.nextInt((122 - 97) + 1) + 97);
		
		return randomString;
	}
	
	/**
	* Pads the length of a key with 0's to 12-bytes.
	* @param key the key that is to be padded.
	* @return paddedKey the 12-byte padded key.
	*/
	public static String padKey(String key) 
	{
		
		if (key.length() >= 12)
			return null;
		
		String padding = "";
			
		for(int i = 0; i < (12-key.length()); i++)
			padding += "0";
			
		return (padding + key);
	}
	
	/**
	* Hashes a String value using MD5 and returns the hashed version of the original value.
	* @param value the value that is to be hashed using the MD5 algorithm.
	* @return hashedValue the hashed state of the original value.
	*/
	public static byte[] hashUsingMD5(String value) 
	{
		byte[] hashedValue = null;
		byte[] bytesOfMessage = null;
			
		try 
		{
			bytesOfMessage = value.getBytes("UTF-8");
			MessageDigest messageHash = MessageDigest.getInstance("MD5");
			hashedValue = messageHash.digest(bytesOfMessage);
		} 
		catch(NoSuchAlgorithmException e) 
		{
			System.err.println("Couldn't find the selected algorithm.");
		}
		catch(UnsupportedEncodingException e) 
		{
			System.err.println("Invalid encoding scheme.");
		} 
		
		return hashedValue;
	}
	
	/**
	* Decodes a String message using BASE64 decoding and decrypts it using AES/CBC/PKCS5PADDING.
	* @param encryptedMessage the encrypted message that is to be decoded and decrypted.
	* @param iv the initialisation vector required to decrypt the encrypted message.
	* @param sessionKey the secret key required to decrypt the encrypted message.
	* @return decryptedMessage the decrypted message with any excess characters removed.
	*/
	public static String decodeAndDecrypt(String encryptedMessage, String iv, byte[] sessionKey)
	{
		//--> Decode the encrypted message from BASE64.
		byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);
		String decryptedMessage = "";
			
		try 
		{   
			//--> Decrypt the decoded message.
			IvParameterSpec ivParameterSpec  = new IvParameterSpec(iv.getBytes("UTF-8"));
			SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
			decryptedMessage = new String(cipher.doFinal(decodedMessage), Charset.forName("UTF-8"));				
		} 
		catch(NoSuchAlgorithmException e) 
		{
			System.err.println("Couldn't find the selected algorithm.");
		}
		catch(UnsupportedEncodingException e) 
		{
			System.err.println("Invalid encoding scheme.");
		}
		catch(NoSuchPaddingException e) 
		{
			System.err.println("Key is missing padding.");
		}
		catch(InvalidKeyException e) 
		{
			System.err.println("Incorrect key supplied.");
		}
		catch(IllegalBlockSizeException e) 
		{
			System.err.println("Block size is greater than one.");
		}
		catch(BadPaddingException e) 
		{
			System.err.println("Invalid key supplied for decryption.");
		}
		catch(InvalidAlgorithmParameterException e) 
		{
			System.err.println("Invalid parameters supplied for AES algorithm.");
		}
		
		//--> Remove the 'FILE' tag from the encrypted message and return it.
		return decryptedMessage.substring(5, decryptedMessage.length());
	}
	
	/**
	* Encodes a String message using BASE64 encoding and encrypts it using AES/CBC/PKCS5PADDING.
	* @param plaintextMessage the plaintext message that is to be encoded and encrypted.
	* @param iv the initialisation vector required to encrypt the plaintext message.
	* @param sessionKey the secret key required to encrypt the plaintext message.
	* @return encryptedMessage the encrypted message with any excess characters removed.
	*/
	public static String encodeAndEncrypt(String plaintextMessage, String iv, byte[] sessionKey) {
		
		String encryptedMessage = "";
		byte[] encryptedDecryptedMessage = null;
			
		try 
		{
			MessageDigest messageHash = MessageDigest.getInstance("MD5");
			encryptedDecryptedMessage = messageHash.digest(plaintextMessage.getBytes("UTF-8"));
			
			IvParameterSpec ivParameterSpec  = new IvParameterSpec(iv.getBytes("UTF-8"));
			SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
			byte[] encryptedBytes = cipher.doFinal(encryptedDecryptedMessage);
				
			encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
		} 
		catch(NoSuchAlgorithmException e) 
		{
			System.err.println("Couldn't find the selected algorithm.");
		}
		catch(UnsupportedEncodingException e) 
		{
			System.err.println("Invalid encoding scheme.");
		}
		catch(NoSuchPaddingException e) 
		{
			System.err.println("Key is missing padding.");
		}
		catch(InvalidKeyException e) 
		{
			System.err.println("Incorrect key supplied.");
		}
		catch(IllegalBlockSizeException e) 
		{
			System.err.println("Block size is greater than one.");
		}
		catch(BadPaddingException e) 
		{
			System.err.println("Invalid key supplied for decryption.");
		}
		catch(InvalidAlgorithmParameterException e)
		{
			System.err.println("Invalid parameters supplied for AES algorithm.");
		}
		
		return encryptedMessage;
	}
}


























