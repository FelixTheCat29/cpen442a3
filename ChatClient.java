import java.security.SecureRandom;
import org.apache.commons.codec.binary.Base64;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;

import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class ChatClient {
	
    static BigInteger primeP = new BigInteger("18842123997897468384827896685993931781080181932353719187439050230076503205491514062816121897948449538686354578795440785175631789523548171283166673215872826064966256603674601777255817882880016074704308760295612120774436825003902983799470234885065892282430228639538213926322446322124930136312026409312000822287033431257235423023809533190703435787388765938383480718020440676276625252109883249965567340323727374334524350798148993371393712671181960344081862582200306195981896884420852572678422392582013814637813963228898407781704195321567767242393529190241129465519542431613593652359374078373798987402908944447964101601319");
    static BigInteger generatorG = new BigInteger(Integer.toString(2));
    static BigInteger sessionKey;
    static String sessionKeyStr;
    BigInteger client_secret_bi;
    static BigInteger modulus;
    static String modulus_string;
    static String IV = "AAAAAAAAAAAAAAAA";  
    int nonce_client = 1;
    static boolean auth =false;
    
    static SecureRandom rand = new SecureRandom();
    static int client_secret;
    static String secretKey;
    BufferedInputStream in;
    
    PrintWriter out;
    JFrame frame = new JFrame("Client");
    JTextField textField = new JTextField(120);
    static JTextArea messageArea = new JTextArea(20, 120);

    public ChatClient() throws NumberFormatException, IOException {
        // Generate random secret
    	client_secret = rand.nextInt(Integer.MAX_VALUE - 2048) + 2048;
    	client_secret_bi = new BigInteger(Integer.toString(client_secret));
    	
    	// Create file to store odd nonce (which increments)
    	BufferedReader reader = null;
    	
    	File file = new File("./nonce_client.txt");
    	if(!file.exists()) {
    	    file.createNewFile();
    	}else {
	    	reader = new BufferedReader(new FileReader(file));
	        String text = null;
	        while ((text = reader.readLine()) != null) {
	            nonce_client = (Integer.parseInt(text));
	            System.out.println("nonce client old: " + nonce_client);
	            nonce_client += 2;

	            show("Nonce client: " + nonce_client);
	        }   	
	        reader.close();
    	}
        PrintWriter writer = new PrintWriter("./nonce_client.txt", "UTF-8");
        System.out.println("writing nonce_client.txt: " + nonce_client);
        writer.println(nonce_client);
        writer.close();
    	
        // Layout GUI
        textField.setEditable(false);
        messageArea.setEditable(false);
        frame.getContentPane().add(textField, "North");
        frame.getContentPane().add(new JScrollPane(messageArea), "Center");
        frame.pack();

        // Add Listeners
        textField.addActionListener(new ActionListener() {
            /**
             * Responds to pressing the enter key in the textfield by sending
             * the contents of the text field to the server.    Then clear
             * the text area in preparation for the next message.
             */
            public void actionPerformed(ActionEvent e) {
            	String plaintext = textField.getText();
            	if(plaintext.length() > 0){
	            
	            	try {
						byte[] ciphertext = encrypt(plaintext, sessionKeyStr);
					
						String to_server = "MS" + new String(ciphertext);
						show("-----------------------------------------------");
						show("To server: " + to_server);
						out.println(to_server);
						
						// Update message area
						show("Client: " + plaintext);
		                textField.setText("");
		                
					} catch (Exception e1) {
						e1.printStackTrace();
						System.out.println("Encrypting text message failed");
					}
            	}
            }
        });
    }

    /**
     * Prompt for and return the address of the server.
     */
    private String getServerAddress() {
        return JOptionPane.showInputDialog(
            frame,
            "Enter IP Address of the Server:",
            "IPAddress",
            JOptionPane.QUESTION_MESSAGE);
    }
    /**
     * Prompt for and return the secret key of the server.
     */
    private String getSecretKey() {
        return JOptionPane.showInputDialog(
            frame,
            "Enter Secret Key:",
            "SecretKey",
            JOptionPane.QUESTION_MESSAGE);
    }
    
    // Show text on chat message area on new line
    public static void show(String text){
    	messageArea.append(text + "\n");
    }
    
    public static int getPadLen(String plainText) {
        return 16 - plainText.length()%16;
    }
    
    public static byte[] encrypt(String plainText, String encryptionKey) throws Exception {
    
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        System.out.println("before: " + plainText);
        int pad_len = 0;
        if((plainText.length()+2)% 16 != 0) {//+2 for padding
        	
        	pad_len = 16 - ((plainText.length()+2)%16); //+2 for padding
        	for(int i=0; i< pad_len; i++) {
        		plainText = plainText + "0";
        	}
        }
        // Encrypt the padding as well
        String pad_len_str = String.format("%02d", pad_len);
        String p = pad_len_str + plainText;
        System.out.println("after: " + plainText);
        
        byte[]  encodedKey = secretKey.getBytes();
        Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
        return Base64.encodeBase64(cipher.doFinal(p.getBytes()));
    }
    
      public static String decrypt(byte[] cipherText, String encryptionKey, int length) throws Exception{
        
        byte[] cipherTextCropped = Arrays.copyOfRange(cipherText, 2, length); // get rid of header
        byte[] decodedText = Base64.decodeBase64(cipherTextCropped);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        byte[] encodedKey = secretKey.getBytes();
        
        Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes()));
        String deciphered_text = new String(cipher.doFinal(decodedText));
        
        int padlen = Integer.parseInt(deciphered_text.substring(0,2)); // Extract padding length
        return deciphered_text.substring(2, decodedText.length-padlen); //Does not remove delimiters
      }
      
      public static String make16Bytes(String in) {
      	
      	if (in.length() < 16) {
      		int padlen = 16 - in.length()%16;
      		for(int i = 0; i < padlen; i++) {
      			in = in + "0";
      		}
      		return in;
      		
      	} else if (in.length() > 16){
      		
      		return in.substring(0, 16);
      	}
      	return in;
      }

    private void run() throws IOException {
    	
        // Make connection and initialize streams
        String serverAddress = getServerAddress();
        secretKey = getSecretKey();
        show("Secret key: " + secretKey);
        secretKey = make16Bytes(secretKey);
        show("Secret key is now 16 bytes: " + secretKey);
        
        Socket socket = new Socket(serverAddress, 9001);
        in = new BufferedInputStream(socket.getInputStream());
        out = new PrintWriter(socket.getOutputStream(), true);        
        
        // Process all messages from server, according to the protocol.
        while (true) {
            
            byte[] lineBytes = new byte[4000];
            
            int length_bytes = in.read(lineBytes) - 2; //2 extra bytes are counted for, remove here
            System.out.println("Length bytes " + length_bytes);
            
            if (length_bytes > 0 ){
            	
				byte[] legitBytes = Arrays.copyOf(lineBytes, length_bytes);
				
				String line = new String(legitBytes);
				
				System.out.println("Received " + line);
				
	           if (line.startsWith("MS")) {
	            	try {
	            		show("-----------------------------------------------");
	            		show("From server: " + line);
						String plaintext = decrypt(legitBytes, sessionKeyStr, length_bytes);
						show("Decrypted plaintext from server: " + plaintext);
						
					} catch (Exception e) {
						e.printStackTrace();
						System.out.println("Message decryption failed");
					}
	            } else if (line.startsWith("SUBMITNONCE")) {
	            	out.println(nonce_client);
	            } else if (line.startsWith("NONCEACCEPTED")) {
	            	show("Nonce accepted");
	            } else if (line.startsWith("E1")){
	    		
	    			try {
	    				// Parse server nonce which is unencrypted
	    				int nonce_server_end = line.indexOf(';');
						String nonce_server = line.substring(2, nonce_server_end);
						show("Nonce from server: " + nonce_server);

						// Make sure nonce is even
						int nonce_server_should_be_even = Integer.parseInt(nonce_server);
						if (nonce_server_should_be_even %2 == 1) {
							show("********** AUTH FAILED INCORRECT NONCE ************");
						} else {
							
							byte[] decryptBytes = Arrays.copyOfRange(legitBytes, nonce_server_end-1, length_bytes);
							System.out.println("DecryptBtes length "+ decryptBytes.length);
							String dtext = decrypt(decryptBytes, secretKey, length_bytes - nonce_server_end+1);
							show("Decrypted plaintext from server: " + dtext);
							
							// Parse nonce
							int nonce_end = dtext.indexOf(';');
							int nonce_check = Integer.parseInt(dtext.substring(0, nonce_end));
							show("Nonce check: " + nonce_check);
							
							// Check nonce is equal
							if (nonce_check == nonce_client) {
								show("********** Nonces are equal. Authenticated **********");
								
								// Parse the modulus from server
								int modulus_end = dtext.indexOf(';', nonce_end +1);
								String server_modulus = dtext.substring(nonce_end+1, modulus_end);
								show("g^b mod p: " + server_modulus);
								
								BigInteger server_modulus_bi = new BigInteger(server_modulus);
								
								// Calculate session key from server modulus and client secret and primeP.
								sessionKey = server_modulus_bi.modPow(client_secret_bi, primeP);
								sessionKeyStr = make16Bytes(sessionKey.toString(10));
								show("Session key (g^(a*b) mod p): " + sessionKey);
								show("********** Session key established **********");
								
								// Send the server nonce back plus client's modulus					        
								String plainText = nonce_server + ";" + modulus_string + ";";
								
								// Encrypt the plainText
				            	byte[] ciphertext = encrypt(plainText, secretKey);
				            	String c = new String(ciphertext);
				            	
				            	// Send cipherText over the socket
				            	String to_server = "E2" + c;
				            	show("To server: " + to_server);
								out.println(to_server);
								System.out.println("Sent over: " + to_server);
	
								// Now we have a session key, we can talk
								textField.setEditable(true);
								
							} else {
								show("********** AUTH FAILED ************");
							}
						}
					} catch (Exception e) {
						e.printStackTrace();
						System.out.println("Decrypt failed");
					}
	    		}
	        }
        }
    }
   
    /**
     * Runs the client as an application with a closeable frame.
     */
    public static void main(String[] args) throws Exception {
        ChatClient client = new ChatClient();
        BigInteger client_secret_bi = new BigInteger(Integer.toString(client_secret));
        modulus = generatorG.modPow(client_secret_bi, primeP);
        modulus_string = modulus.toString(10);
        show("Prime: " + primeP.toString(10));
        show("Generator: " + generatorG.toString(10));
        show("Client secret (a) : " + client_secret_bi);
        show("Client modulus (g^a mod p) : " + modulus);
        System.out.println("Client secret " + client_secret);
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);
        client.run();
    }
}