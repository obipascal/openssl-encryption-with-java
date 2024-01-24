import javax.crypto.Cipher;  
import javax.crypto.SecretKey;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.IvParameterSpec;  
import javax.crypto.spec.PBEKeySpec;  
import javax.crypto.spec.SecretKeySpec;  
import java.nio.charset.StandardCharsets;  
import java.security.InvalidAlgorithmParameterException;  
import java.security.InvalidKeyException;  
import java.security.NoSuchAlgorithmException;  
import java.security.spec.InvalidKeySpecException;  
import java.security.spec.KeySpec;  
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;  
import javax.crypto.IllegalBlockSizeException;  
import javax.crypto.NoSuchPaddingException;  

public class Encrypter {
      /* Private variable declaration */  
      private static final String SECRET_KEY = "123456789";  
      private static final String SALTVALUE = "abcdefg";  
     
      /* Encryption Method */  
      public static String encrypt(String payload, String passwordKey)   
      {  
        try   
        {  
            /* Declare a byte array. */  
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  
            IvParameterSpec ivspec = new IvParameterSpec(iv);        
            
            /* Create factory for secret keys. */  
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
            /* PBEKeySpec class implements KeySpec interface. */  
            KeySpec spec = new PBEKeySpec(passwordKey.toCharArray(), passwordKey.getBytes(), 65536, 256);  
            SecretKey tmp = factory.generateSecret(spec);  
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
            

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec); 
            
            
            /* Retruns encrypted value. */  
            return Base64.getEncoder()  
    .encodeToString(cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8)));  
        }   
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
        {  
            System.out.println("Error occured during encryption: " + e.toString());  
        }  
      return null;  
      }  
      
      /* Decryption Method */  
      public static String decrypt(String payload, String passwrdKey)   
      {  
        try   
        {  
            /* Declare a byte array. */  
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  
            IvParameterSpec ivspec = new IvParameterSpec(iv);  
            
            /* Create factory for secret keys. */  
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  
            /* PBEKeySpec class implements KeySpec interface. */  
            KeySpec spec = new PBEKeySpec(passwrdKey.toCharArray(), passwrdKey.getBytes(), 65536, 256);  
            SecretKey tmp = factory.generateSecret(spec);  
            
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");  
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");  
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);  
            /* Retruns decrypted value. */  
            return new String(cipher.doFinal(Base64.getDecoder().decode(payload)));  
        }   
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)   
        {  
            System.out.println("Error occured during decryption: " + e.toString());  
        }  
        return null;  
      }  
    
      public static String encodeBase64(String s) {
            return Base64.getEncoder().encodeToString(s.getBytes());
        }

        public static String decodeBase64(String s) {
            try {
                if (isBase64(s)) {
                    return new String(Base64.getDecoder().decode(s));
                } else {
                    return s;
                }
            } catch (Exception e) {
                return s;
            }
        }

        public static boolean isBase64(String s) {
            String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
            Pattern r = Pattern.compile(pattern);
            Matcher m = r.matcher(s);

            return m.find();
        }
      /* Driver Code */  
      public static void main(String[] args)   
      {  
          /* Message to be encrypted. */  
          String payloadData = "Data sent to server";
          String passKey = "Pascalobi12$";
          /* Call the encrypt() method and store result of encryption. */  
          String encryptedval = encrypt(payloadData, passKey);  
          /* Call the decrypt() method and store result of decryption. */  
          String decryptedval = decrypt(encryptedval,passKey);  
          /* Display the original message, encrypted message and decrypted message on the console. */  
          System.out.println("Original value: " + payloadData);  
          System.out.println("Encrypted value: " + encryptedval);  
          System.out.println("Decrypted value: " + decryptedval);  
      }  
}
