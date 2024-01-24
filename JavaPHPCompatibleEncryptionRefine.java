
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;  
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
 
public class JavaPHPCompatibleEncryptionRefine {
 
    private static String CIPHER_NAME = "AES/CBC/PKCS5PADDING";
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
 
    public static final String ENCRYPTION_KEY = "u7k3g4e6n7t6h7l2"; // 128 bit key
    public static final String ENCRYPTION_IV = "9876543210fedcba"; // 16 bytes IV
    public static final int ITERATION_COUNT = 10000; // Interation count
    public static final int KEY_LENGTH = 256; // key bytes leight
 
 

    public static void encryptToHex(String key, String iv, String data) {
        try {


            IvParameterSpec initVector = new IvParameterSpec(iv.getBytes("UTF-8"));


            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(key.toCharArray(),
                    key.getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey  tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, initVector);


            String base64_EncryptedData = Base64.getEncoder()
                    .encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
            String base64_IV = Base64.getEncoder().encodeToString(iv.getBytes("UTF-8"));

            return asciiToHex(base64_EncryptedData + ":" + base64_IV);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
 
        return null;
    }
 
 
    public static String decryptFromHex(String key,  String hexdata) {
        try {
            String data = hexToAscii(hexdata);

            String[] parts = data.split(":");

            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(parts[1]));

            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(key.toCharArray(),
                    key.getBytes(StandardCharsets.UTF_8), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

            byte[] decodedEncryptedData = Base64.getDecoder().decode(parts[0]);
            return  new String(cipher.doFinal(decodedEncryptedData),
                    StandardCharsets.UTF_8);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
 
        return null;
    }
 
    
    private static String asciiToHex(String asciiStr) {
        char[] chars = asciiStr.toCharArray();
        StringBuilder hex = new StringBuilder();
        for (char ch : chars) {
            hex.append(Integer.toHexString((int) ch));
        }
 
        return hex.toString();
    }
 
    private static String hexToAscii(String hexStr) {
        StringBuilder output = new StringBuilder("");
 
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
 
        return output.toString();
    }


 
    public static void main(String[] args) {
 
        String input = "Obi Pascal Banjuare";
        String enc = encryptToHex(ENCRYPTION_KEY, ENCRYPTION_IV, input);
        String dec = decryptFromHex(ENCRYPTION_KEY,enc);
        System.out.println("Input Text     : " + input);
        System.out.println("Encrypted Text : " + enc);
        System.out.println("Decrypted Text : " + dec);
    }
}
