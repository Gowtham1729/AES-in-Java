

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;


public class AES_Encryption
{
    static String plainText = ",,110980,2,280010,280022,280022_admin,4,2019/05/01 23:59:59";
    private static final String ENCRYPT_KEY = "BA74911B90F408FCE34405EB0FC86785";
    
    public static void main(String[] args) throws Exception
    {
        
        byte[] keyByte = ENCRYPT_KEY.substring(0, 16).getBytes("UTF-8"); //changed from .getBytes("UTF-8") to .substring(0, 16).getBytes("UTF-8");
        SecretKeySpec key = new SecretKeySpec(keyByte, "AES");

      	String message = "YGjn9KxxMqwscT4KtirjnR03BhWOL2jMxqrXd2W8+lBN2nNZnNWdufLhHh8i+bGBACvd5LIpbxvC1zfXya3Vjw==";
      	//key.substring(0, 16).getBytes("UTF-8")
      	byte[] cipherText = Base64.getDecoder().decode(message.getBytes("UTF-8"));
        byte[] IV = Base64.getDecoder().decode("SwA/qJVOPn+2tRo0LbYorA==".getBytes("UTF-8"));
      	
      	System.out.println("Text : " + plainText);
      	System.out.println("message : " + message);
      	System.out.println("encrypted message in bytes: " + cipherText);
      	System.out.println("IV:" + IV);
      	System.out.println("key : " + key);
      	
      	//byte[] cipherText = encrypt(plainText.getBytes(),key, IV);
        System.out.println("Encrypted Text : "+Base64.getEncoder().encodeToString(cipherText));
      
        //System.out.println("Original Text  : "+plainText);
        
        String decryptedText = decrypt(cipherText,key, IV);
        System.out.println("DeCrypted Text : "+decryptedText);
        
    }
    
    public static byte[] encrypt (byte[] plaintext,SecretKey key,byte[] IV ) throws Exception
    {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        
        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        //Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);
        
        return cipherText;
    }
    
    public static String decrypt (byte[] cipherText, SecretKey key,byte[] IV) throws Exception
    {
        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      	
      	//System.out.println(key);
        
        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        
        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        
        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);
        
        return new String(decryptedText);
    }
}


