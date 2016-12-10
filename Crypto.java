/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkg1312084.pkg1312110;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import static java.lang.System.exit;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.Random;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;


/**
 *
 * @author Quang Dai
 */
public class Crypto {
   
    SecretKey secret;
    public PublicKey pub;
    PrivateKey pri;
    public KeyPair kp;
    
    public String RandomString (int length) {
        
        char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            char c = chars[random.nextInt(chars.length)];
            sb.append(c);
        }
        return sb.toString();
    }
    
    //generate secret key
    public SecretKey secretKeyGen(String type, int size) throws NoSuchAlgorithmException {
        
        KeyGenerator keyGen = KeyGenerator.getInstance(type);
        keyGen.init(size);
        return keyGen.generateKey();
    }
    
    //generate key pair
    public void generateKeys(int size) throws Exception {
        
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair keyPair = kpg.generateKeyPair();
	this.kp = keyPair;
	this.pub = keyPair.getPublic();
	this.pri = keyPair.getPrivate();
    }
    
    //Load PubKey
    public PublicKey ReadPublicKey (String path) throws Exception {
        
        //Read XML File
        File filePublicKey = new File(path);
	DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
	Document doc = dBuilder.parse(filePublicKey);
        
        NodeList pubList = doc.getElementsByTagName("PublicKey");
        Node t = pubList.item(0);
        
	String encodedPublicKey = t.getTextContent();
	
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey.getBytes());
	PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }
    
    //Load PriKey
    private PrivateKey ReadPrivateKey (String path) throws Exception {
        
        //Read XML File
        File filePrivateKey = new File(path);
	DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
	Document doc = dBuilder.parse(filePrivateKey);
        
        NodeList priList = doc.getElementsByTagName("PrivateKey");
        Node t = priList.item(0);
        
	String encodedPrivateKey = t.getTextContent();
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey.getBytes());
	PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }
    
    
    //Encrypt Secret Key
    public byte[] EncryptSecretKey (PublicKey pubkey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

	Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
	return cipher.doFinal(this.secret.getEncoded());
    }
    
    //Encrypt Padding Scheme, Mode of Operation, IVByte, Type
    public byte[] EncryptInfomation (String temp, PublicKey pubkey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

	Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubkey);
	return cipher.doFinal(temp.getBytes());
    }
    
    //Encrypt Mode Of Operation

    public void EncryptFile (String path, String source, String dest, String typeofencrypt, String mode, String padding) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception {
        
        String temp = typeofencrypt + "/" + mode + "/" + padding;

        //Random IV and Secret Key
        String ivBytes = "";
       
        if (typeofencrypt.equals("AES"))
        {
            ivBytes = RandomString(16);
            this.secret = this.secretKeyGen("AES", 128);
            
        }
        
        if (typeofencrypt.equals("DES"))
        {
            ivBytes = RandomString(8);
            this.secret = this.secretKeyGen("DES", 64);
        }
        
        //Đọc dữ liệu từ file plaintext
        File file = new File(source);
        byte [] byteEncrypt = new byte [(int) file.length()];
        FileInputStream fis = new FileInputStream(file);
        fis.read(byteEncrypt);
        fis.close();

        //Encrypt content of file
        IvParameterSpec iv = new IvParameterSpec(ivBytes.getBytes());
        Cipher cipher = Cipher.getInstance(temp);
        cipher.init(Cipher.ENCRYPT_MODE, this.secret, iv);
        byte[] encrypted = cipher.doFinal(byteEncrypt);
//        Base64.Encoder encoder = Base64.getEncoder();
//        String encryptedText = encoder.encodeToString(encrypted);


        //Encrypt Secret Key
        PublicKey pubRecv = this.ReadPublicKey(path);
        byte[] SecretKeyEncrypted = this.EncryptSecretKey(pubRecv);
        
        //Encrypt Padding Scheme and Mode Of Operation and Type 
        byte[] PaddingEncrypted = this.EncryptInfomation(padding, pubRecv);
        byte[] ModeEncrypted = this.EncryptInfomation(mode, pubRecv);
        byte[] TypeEncrypted = this.EncryptInfomation(typeofencrypt, pubRecv);
        byte[] ivEncrypted = this.EncryptInfomation(ivBytes, pubRecv);
        
        //Ghi vào file output
        File output = new File (dest);
        FileOutputStream os2 = new FileOutputStream(output);
        
        String temp1 = "\r\n"; //chèn ý tự xuống dòng cho dễ phân biệt
        os2.write(SecretKeyEncrypted);
        os2.write(temp1.getBytes());
        os2.write(typeofencrypt.getBytes());
        os2.write(temp1.getBytes());
        os2.write(PaddingEncrypted);
        os2.write(temp1.getBytes());
        os2.write(ModeEncrypted);
        os2.write(temp1.getBytes());
        os2.write(ivEncrypted);
        os2.write(temp1.getBytes());
        os2.write(encrypted);
        os2.close();
    }
    
    public void decrypt (String source, String dest, String pathkey) throws Exception {
        
        String secretkey, ivString, typeofencrypt, padding, mode, temp;
        
        BufferedReader br = new BufferedReader(new FileReader(source));
        
        PrivateKey privatekey = this.ReadPrivateKey(pathkey);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privatekey);
        
        secretkey = br.readLine();
        typeofencrypt = br.readLine();
        padding = br.readLine();
        mode = br.readLine();
        ivString = br.readLine();
        temp = br.readLine();
        
        br.close();
        
        byte[] SecretKeyDecrypt = cipher.doFinal(secretkey.getBytes());
        byte[] TypeDecrypt = cipher.doFinal(typeofencrypt.getBytes());
        byte[] PaddingDecrypt = cipher.doFinal(padding.getBytes());
        byte[] ModeDecrypt = cipher.doFinal(mode.getBytes());
        byte[] IVDecrypt = cipher.doFinal(ivString.getBytes());
        
        String temp2 = TypeDecrypt.toString() + "/" + ModeDecrypt.toString() + "/" + PaddingDecrypt.toString();
        IvParameterSpec iv = new IvParameterSpec(ivString.getBytes());
        SecretKeySpec skeySpec = new SecretKeySpec(SecretKeyDecrypt, TypeDecrypt.toString());
        Cipher ciphercontent = Cipher.getInstance(temp2);
        ciphercontent.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] decrypted = cipher.doFinal(temp.getBytes());
        
        File output = new File (dest);
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(decrypted);
        fos.close();
    }
    
    public void Sign (String path, String pathkey) throws FileNotFoundException, IOException, Exception
    {
        // Read File
        File file = new File(path);
	FileInputStream fis = new FileInputStream(path);
	byte[] data = new byte[(int) file.length()];
	fis.read(data);
	fis.close();
        
        //Read PrivateKey
        PrivateKey priKey = this.ReadPrivateKey(pathkey);
        
        //Hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        
        //Sign
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(priKey);
        signature.update(hash);
        byte [] signatureBytes = signature.sign();
        
        //Get Filename
        int index1 = path.lastIndexOf("/");
        String filename = path.substring(index1+1, path.length() - 1) + ".sig";
        
        //Write Signature to File
        File signfile = new File (filename);
        FileOutputStream os = new FileOutputStream(signfile);
        os.write(signatureBytes);
        os.close();
    }
    
    public void Verify (String pathfile, String pathfilesign, String pathkey) throws FileNotFoundException, IOException, Exception
    {   
        File signfile = new File (pathfilesign);
        if (signfile.exists()) //Signature File is exits!!!
        {
            FileInputStream fis_sign = new FileInputStream(signfile);
            byte[] signature = new byte[(int) signfile.length()];
            fis_sign.read(signature);
            fis_sign.close();
            
            // Read File
            File file = new File(pathfile);
            FileInputStream fis = new FileInputStream(pathfile);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            //Read PrivateKey
            //Chỗ này tui chưa biết cách duyệt từng publickey nhen Bự
            PublicKey pubKey = this.ReadPublicKey(pathkey);

            //Hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);

            //Verify
            Signature verifier = Signature.getInstance("SHA256WithRSA");
            verifier.initVerify(pub);
            verifier.update(hash);
            if (verifier.verify(signature)) 
            {
                System.out.println("SIGNATURE IS VALID!!!");
            } 
            else 
            {
                System.out.println("SIGNATURE IS INVALID!!!");
            }
        }
        else
        {
            System.out.println("SIGNATURE FILE IS NOT EXISTS!!!");
        }
    }
}
