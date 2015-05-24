package Utilities;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.HashMap;

/**
 * A tester for the CryptoUtils class.
 *
 * @author www.codejava.net
 */
public class CryptoUtilsTest {
    public static void main(String[] args) {
        String key = "verygoodpassword";
        File inputFile = new File("files/usersInformationDecrypted");
        File encryptedFile = new File("files/usersInformationEncrypted");
        File decryptedFile = new File("files/usersInformationDecrypted");
        HashMap<String,String> hash = new HashMap<String, String>();
        hash.put("rfsimoes","benfica");
        hash.put("amdinis","porto");

        try {
            decryptedFile.createNewFile();
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("files/usersInformationDecrypted"));
            //oos.writeObject("rfsimoes benfica");
            oos.writeObject(hash);
            encryptedFile.createNewFile();
            CryptoUtils.encrypt(key, inputFile, encryptedFile);
            //CryptoUtils.decrypt(key, encryptedFile, decryptedFile);
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}