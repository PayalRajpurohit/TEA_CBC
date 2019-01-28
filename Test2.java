import java.security.SecureRandom;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test2{
	
	private final static int IDELTA = 0x9E3779B9;
	private final static int VALUE  = 32;
	private final static int ODELTA = 0xC6EF3720;

	private int[] y = new int[4];
	
	public Test2(byte[] KEY) {
		if (KEY == null)
			throw new RuntimeException("Key is null");
		if (KEY.length < 16)
			throw new RuntimeException("Length is less than 16 bytes");
		for (int x=0, i=0; i<4; i++) {
			y[i] = ((KEY[x++] & 0xff)) |
			((KEY[x++] & 0xff) <<  8) |
			((KEY[x++] & 0xff) << 16) |
			((KEY[x++] & 0xff) << 24);
		}
	}
	
	public byte[] encrypt(byte[] data) {
		int pSize = ((data.length/8) + (((data.length%8)==0)?0:1)) * 2;
		int[] buff = new int[pSize + 1];
		buff[0] = data.length;
		wrap(data, buff, 1);
		en_meth(buff);
		return unwrap(buff, 0, buff.length * 4);
	}

	
	public byte[] decrypt(byte[] crypted_text) {
		assert crypted_text.length % 4 == 0;
		assert (crypted_text.length / 4) % 2 == 1;
		int[] buff = new int[crypted_text.length / 4];
		wrap(crypted_text, buff, 0);
		de_meth(buff);
		return unwrap(buff, 1, buff[0]);
	}

	void en_meth(int[] buffer) {
		int z0, z1, sum,i, n;
		assert buffer.length % 2 == 1;
		i = 1;
		while (i<buffer.length) {
			n = VALUE;
			z0 = buffer[i];
			z1 = buffer[i+1];
			sum = 0;
			while (n-->0) {
				sum += IDELTA;
				z0  += ((z1 << 4 ) + y[0] ^ z1) + (sum ^ (z1 >>> 5)) + y[1];
				z1  += ((z0 << 4 ) + y[2] ^ z0) + (sum ^ (z0 >>> 5)) + y[3];
			}
			buffer[i] = z0;
			buffer[i+1] = z1;
			i+=2;
		}
	}
	
	void de_meth(int[] buffer) {
		int  z0, z1, sum,i, n;
		assert buffer.length % 2 == 1;
		i = 1;
		while (i<buffer.length) {
			n = VALUE;
			z0 = buffer[i]; 
			z1 = buffer[i+1];
			sum = ODELTA;
			while (n--> 0) {
				z1  -= ((z0 << 4 ) + y[2] ^ z0) + (sum ^ (z0 >>> 5)) + y[3];
				z0  -= ((z1 << 4 ) + y[0] ^ z1) + (sum ^ (z1 >>> 5)) + y[1];
				sum -= IDELTA;
			}
			buffer[i] = z0;
			buffer[i+1] = z1;
			i+=2;
		}
	}
	
	void wrap(byte[] start, int[] end, int end_off) {
		assert end_off + (start.length / 4) <= end.length;
		int i = 0, shift = 24;
		int j = end_off;
		end[j] = 0;
		while (i<start.length) {
			end[j] |= ((start[i] & 0xff) << shift);
			if (shift==0) {
				shift = 24;
				j++;
				if (j<end.length) end[j] = 0;
			}
			else {
				shift -= 8;
			}
			i++;
		}
	}
	
	byte[] unwrap(int[] start, int start_off, int endlen) {
		assert endlen <= (start.length - start_off) * 4;
		byte[] end = new byte[endlen];
		int i = start_off;
		int count = 0;
		for (int j = 0; j < endlen; j++) {
			end[j] = (byte) ((start[i] >> (24 - (8*count))) & 0xff);
			count++;
			if (count == 4) {
				count = 0;
				i++;
			}
		}
		return end;
	}
	
	 public static byte[] encryptCBC (byte[] original_text,SecretKey key,byte[] IV ) throws Exception
    {
        //Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        //Creating SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        //Creating IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        
        //Initializing Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        //Performing Encryption
        byte[] cipherText = cipher.doFinal(original_text);
        
        return cipherText;
    }
	
	 public static String decryptCBC (byte[] cipherText, SecretKey k,byte[] iv) throws Exception
    {
        //Getting Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        //Creating SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(k.getEncoded(), "AES");
        
        //Creating IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        //Initializing Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        //Performing Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }

	 public static void main(String[] args) throws Exception
    {
		System.out.println("Enter what you to encrypt");
		Scanner sc = new Scanner(System.in);
		String original_text = sc.nextLine();
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);

        // Generating Key
        SecretKey k = keyGen.generateKey();

        // Generating IV.
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
		
		System.out.println("Plain Text entered by User : "+original_text );
		
		byte[] cipher_Text = encryptCBC(original_text.getBytes(),k, IV);
        System.out.println("Encrypted Text using CBC : "+Base64.getEncoder().encodeToString(cipher_Text) );
		
		Test2 obj = new Test2(cipher_Text);
		
		byte[] crypted_text = obj.encrypt(cipher_Text);
		System.out.println("Encrypted Text using TEA : "+Base64.getEncoder().encodeToString(crypted_text));
		
		byte[] result = obj.decrypt(crypted_text);
		System.out.println("Decrypted Text using TEA : "+Base64.getEncoder().encodeToString(result));
		
		String decrypted_Text = decryptCBC(result,k, IV);
        System.out.println("DeCrypted Text using CBC : "+decrypted_Text);
		
		
	}
	
	}
