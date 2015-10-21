import java.security.SecureRandom;
import org.apache.commons.codec.binary.Base64;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class ChatServer {
	
    static BigInteger primeP = new BigInteger("18842123997897468384827896685993931781080181932353719187439050230076503205491514062816121897948449538686354578795440785175631789523548171283166673215872826064966256603674601777255817882880016074704308760295612120774436825003902983799470234885065892282430228639538213926322446322124930136312026409312000822287033431257235423023809533190703435787388765938383480718020440676276625252109883249965567340323727374334524350798148993371393712671181960344081862582200306195981896884420852572678422392582013814637813963228898407781704195321567767242393529190241129465519542431613593652359374078373798987402908944447964101601319");
    static BigInteger generatorG = new BigInteger(Integer.toString(2));
    static int nonce_server = 0;
    static int nonce_client;
    static String IV = "AAAAAAAAAAAAAAAA";   
    static String secretKey;
    static BigInteger sessionKey;
    static String sessionKeyStr;
    static BigInteger modulus;
    static ServerSocket listener;
    static Socket socket;
    static BigInteger server_secret_bi;
    static boolean auth = false;
    private static final int PORT = 9001;

    static BufferedInputStream in;
    static PrintWriter out;
    static JFrame frame = new JFrame("Server");
    static JTextField textField = new JTextField(120);
    static JTextArea messageArea = new JTextArea(20, 120);
    
    public ChatServer() throws NumberFormatException, IOException {
    	
    	// Layout GUI
        textField.setEditable(false);
        messageArea.setEditable(false);
        frame.getContentPane().add(textField, "North");
        frame.getContentPane().add(new JScrollPane(messageArea), "Center");
        frame.pack();
        
    	// Create file to store even nonce (which increments)
    	BufferedReader reader = null;
    	
    	File file = new File("./nonce_server.txt");
    	
    	if(!file.exists()) {
    	    file.createNewFile();
    	}else {     	 
	    	reader = new BufferedReader(new FileReader(file));
	        String text = null;
	        while ((text = reader.readLine()) != null) {
	            nonce_server = (Integer.parseInt(text));
	            show("Nonce server: " + nonce_server);
	        }   	
	        reader.close();
    	}        
    }

    /* Prompt for and return the secret key of the server. */
    private static String getSecretKey() {
        return JOptionPane.showInputDialog(
            frame,
            "Enter Secret Key:",
            "SecretKey",
            JOptionPane.QUESTION_MESSAGE);
    }
    
    // AES Encryption
    public static byte[] encrypt(String plainText, String encryptionKey) throws Exception {
    	
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        System.out.println("before: " + plainText);
        int pad_len = 0;
        
        // Pad input to be multiple of 16 bytes
        if((plainText.length()+2) % 16 != 0) {	//+2 for padding
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
    
    // AES Decryption
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
    
    // Pad length for 16 bytes
    public static int getPadLen(String plainText) {
        return 16 - plainText.length()%16;
    }
    
    // Show text on chat message area on new line
    public static void show(String text){
    	messageArea.append(text + "\n");
    }
    
    // Function to truncate or append a string to 16 bytes
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
    
    public static void main(String[] args) throws Exception {
        
    	// Init
        ChatServer server = new ChatServer();
        server.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        server.frame.setVisible(true);
        listener = new ServerSocket(PORT);
        
        // Show known values 
        show("Prime: " + primeP.toString(10));
        show("Generator: " + generatorG.toString(10));
        SecureRandom rand = new SecureRandom();
    	int server_secret = rand.nextInt((Integer.MAX_VALUE - 2) + 1) + 3;
        server_secret_bi = new BigInteger(Integer.toString(server_secret));
        modulus = generatorG.modPow(server_secret_bi, primeP);
        show("Server secret (b) : " + server_secret_bi);
        show("Server modulus (g^b mod p) : " + modulus);
        
        // Get secret key
        secretKey = getSecretKey();
        show("Secret key: " + secretKey);
        secretKey = make16Bytes(secretKey);
        show("Secret key is now 16 bytes: " + secretKey);        
        
        while(true){
        	server.run();
        }
    }

    public void run() throws IOException {
    	// Make connection and initialize streams
        socket = listener.accept();
        
        in = new BufferedInputStream (new BufferedInputStream(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        
        

        // Add Listeners
        textField.addActionListener(new ActionListener() {
            
        	// If receive input from text box, encrypt and send to client, update message area
            public void actionPerformed(ActionEvent e) {
            	
            	String plaintext = textField.getText();
            	if(plaintext.length() > 0){
            		
	            	try {
	            		//Send encrypted message to client
						byte[] ciphertext = encrypt(plaintext, sessionKeyStr);
						String to_client = "MS" + new String(ciphertext);
						show("-----------------------------------------------");
						show("To client: " + to_client);
						out.println(to_client);
						
						// Update message area
						show("Server: " + textField.getText());
		                textField.setText("");
		                
					} catch (Exception e1) {
						e1.printStackTrace();
						System.out.println("Message encryption failed");
					}
            	}
            }
        });
    	 try {

            // Get nonce from client
            while (true) {
                out.println("SUBMITNONCE");
                byte[] lineByte = new byte[4000];
                int length = in.read(lineByte) - 2;
                if (length > 0) {
                	byte[] legitBytes = Arrays.copyOf(lineByte,  length);
                	String nonce_str = new String(legitBytes);

                	nonce_client = Integer.parseInt(nonce_str);
                    show("Nonce from client: " + nonce_client);
                    // Check nonce is odd
                    if (nonce_client % 2 == 0 ) {
                    	show("********** AUTH FAILED INCORRECT NONCE ************");
                    } else {
                    	auth = true;
                    }
                    break;
                }
            }
            if (auth) {
            	
            	out.println("NONCEACCEPTED");
            
	            //Send Encrypted Nonce from Client plus modulus calculated from g^b mod p plus nonce odd which is unencrypted
	            //Convert modulus to string for encryption
	            String modulus_string = modulus.toString(10);
	           
	            try {
	            	String plainText = Integer.toString(nonce_client) + ";" + modulus_string + ";"; //Revert later
	            	byte[] ciphertext = encrypt(plainText, secretKey);
	            	
	            	String c = new String(ciphertext);
	            	String to_client = "E1" + Integer.toString(nonce_server) + ";" + c;
					out.println(to_client);
					show("To client: " + to_client);
					
				} catch (Exception e) {
					e.printStackTrace();
					System.out.println("Sending ciphertext failed.");
				}
	            
	            // Get client's modulus and nonce confirmation
	            while (true) {
	           	    byte[] lineByte = new byte[4000];
	                int length = in.read(lineByte) - 2;
	                
	                if (length > 0) {
	                	String line = new String(lineByte);
	                	
	                	if (line.startsWith("E2")) {
		                	byte[] legitBytes = Arrays.copyOf(lineByte,  length);
		                	String dtext;
							try {
								dtext = decrypt(legitBytes, secretKey, length);
								show("Decrypted text from client: " + dtext);
								
								// Get nonce
								int nonce_end = dtext.indexOf(';');
								int nonce_check = Integer.parseInt(dtext.substring(0, nonce_end));
								
								// Check nonce is equal
								if (nonce_check == nonce_server) {
									show("Nonce check: " + nonce_check);
									show("********** Nonces are equal. Authenticated **********");
									
									// Get modulus from client
									int modulus_end = dtext.indexOf(';', nonce_end +1);
									String client_modulus = dtext.substring(nonce_end+1, modulus_end);
									show("g^a mod p: " + client_modulus);
									BigInteger client_modulus_bi = new BigInteger(client_modulus);
									
									// Get session key from server modulus and client secret and primeP.
									sessionKey = client_modulus_bi.modPow(server_secret_bi, primeP);
									sessionKeyStr = make16Bytes(sessionKey.toString(10));
									show("Session key (g^(a*b) mod p): " + sessionKey);
									show("********** Session key established **********");
									
									// Enable text field as now we have a session key to encrypt messages with
									textField.setEditable(true);
								} else {
									show("********** AUTH FAILED ************");
								}
							} catch (Exception e) {
								e.printStackTrace();
								System.out.println("Server decrypt failed");
							}
	                	}
	                	break;
	                }
	            }
	            
	            // Accept messages from this client
	            while (true) {
	            	 byte[] lineByte = new byte[4000];
	                 int length = in.read(lineByte) - 2;
	                 
	                 if (length > 0) {
	                 	byte[] legitBytes = Arrays.copyOf(lineByte, length);
	                 	String line = new String(legitBytes);
	                 	show("-----------------------------------------------");
	                 	show("From client: " + line);
		                try {
							String plaintext = decrypt(legitBytes, sessionKeyStr, length);
							show("Decrypted plaintext from client: " + plaintext);
	
						} catch (Exception e) {
							e.printStackTrace();
							System.out.println("Message decryption failed");
						}
	                 }
	            }
            }
        } catch (IOException e) {
            System.out.println(e);
            
        	PrintWriter writer;
			try {
				// Increment the server's nonce for the next client connection
				nonce_server += 2;
				writer = new PrintWriter("./nonce_server.txt", "UTF-8");
				System.out.println("writing to nonce_server.txt : " + nonce_server);
                writer.println(nonce_server);
                writer.close();
                show("********** Session ended **********");
                show("********** Prepare for new session **********");

                // Show known values
                show("Nonce server: " + nonce_server);
                show("Prime: " + primeP.toString(10));
                show("Generator: " + generatorG.toString(10));
                
                SecureRandom rand = new SecureRandom();
                rand.setSeed(rand.generateSeed(20));
            	int server_secret = rand.nextInt((Integer.MAX_VALUE - 2) + 1) + 3;
                server_secret_bi = new BigInteger(Integer.toString(server_secret));
                modulus = generatorG.modPow(server_secret_bi, primeP);
                show("Server secret (b) : " + server_secret_bi);
                show("Server modulus (g^b mod p) : " + modulus);
                
                // Prompt for the secret key again for the next client connection
                secretKey = getSecretKey();
                show("Secret key: " + secretKey);
                
                // Secret key must be 16 bytes for AES
                secretKey = make16Bytes(secretKey);
                show("Secret key is now 16 bytes: " + secretKey);
                in.close();
                out.close();
                socket.close();
                return;
                
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
				System.out.println("File not found");
			} catch (UnsupportedEncodingException e1) {
				e1.printStackTrace();
				System.out.println("Unsupported encoding");
			}
        

        } finally {
//            try {
//                //socket.close();
//                //listener.close();
//            } catch (IOException e) {
//            	
//            }
        }
    	 
    }
}
