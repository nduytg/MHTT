/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkg1312084.pkg1312110;

import static com.sun.org.apache.xalan.internal.lib.ExsltMath.random;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import static java.lang.Math.random;
import static java.lang.StrictMath.random;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import static jdk.nashorn.internal.objects.NativeMath.random;
import static org.bouncycastle.math.raw.Mod.random;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


/**
 *
 * @author Quang Dai
 */
public class User {
    
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

    public boolean is_Exit (String email, File file) throws Exception {
        
	DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
	DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
	Document doc = dBuilder.parse(file);
        
        NodeList nList = doc.getElementsByTagName("Email");
        for (int i = 0; i < nList.getLength(); i++)
        {
            Node nNode = nList.item(i);
            
            String temp = nNode.getTextContent();
            
            if (temp.equals(email))
            {
                return true;
            }
        }
        return false;
    }
    
    public void Add_Account (File file, String email, String name, String dateofbirth, String phone, String add, String pass) throws IOException, ParserConfigurationException, SAXException, NoSuchAlgorithmException, TransformerConfigurationException, TransformerException, InvalidKeySpecException {
        
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
	DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
	Document doc = docBuilder.parse("Database.xml");

	// Get the root element
	Node Data = doc.getFirstChild();
        
        NodeList nList = doc.getElementsByTagName("User");
        int id = nList.getLength() + 1;
        
        // user elements
        Element user = doc.createElement("User");
        Data.appendChild(user);

        // set attribute to user element
        Attr attr = doc.createAttribute("id");
        attr.setValue(String.valueOf(id));
        user.setAttributeNode(attr);

        //Email elements
        Element MailElement = doc.createElement("Email");
        MailElement.appendChild(doc.createTextNode(email));
        user.appendChild(MailElement);

        //Name elements
        Element NameElement = doc.createElement("Name");
        NameElement.appendChild(doc.createTextNode(name));
        user.appendChild(NameElement);

        //Dateofbirth elements
        Element DateElement = doc.createElement("DateOfBirth");
        DateElement.appendChild(doc.createTextNode(dateofbirth));
        user.appendChild(DateElement);

        //Phone elements
        Element PhoneElement = doc.createElement("Phone");
        PhoneElement.appendChild(doc.createTextNode(phone));
        user.appendChild(PhoneElement);

        //Address elements
        Element AddElement = doc.createElement("Address");
        AddElement.appendChild(doc.createTextNode(add));
        user.appendChild(AddElement);

        //Hash with salt
        String salt = this.RandomString(32);
        String data = salt + pass;
//      KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt.getBytes(), 65536, 128);
//      SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//      byte[] hash = f.generateSecret(spec).getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes());

        //Passphrase elements
        Element PassElement = doc.createElement("Passphrase");
        PassElement.appendChild(doc.createTextNode(hash.toString()));
        user.appendChild(PassElement);

        //Salt elements
        Element SaltElement = doc.createElement("Salt");
        SaltElement.appendChild(doc.createTextNode(salt));
        user.appendChild(SaltElement);
        
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
	Transformer transformer = transformerFactory.newTransformer();
	DOMSource source = new DOMSource(doc);
	StreamResult result = new StreamResult(file);
	transformer.transform(source, result);
    }
    
    public void Sign_In (String email, String name, String dateofbirth, String phone, String add, String pass) throws Exception {
        
        File file = new File("Database.xml");
        
        if (file.exists()) //Đã có file database.xml
        {
            if (this.is_Exit(email, file) == false) //chưa tồn tại tài khoản này
            {
                this.Add_Account(file, email, name, dateofbirth, phone, add, pass);
            }
            else //đã tồn tại tài khoản này
            {
                System.out.println("Email have already exists!!!");
            }
        }
        else //Chưa có file database.xml
        {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

            // root elements
            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("Data");
            doc.appendChild(rootElement);
            
            // user elements
            Element user = doc.createElement("User");
            rootElement.appendChild(user);

            // set attribute to user element
            Attr attr = doc.createAttribute("id");
            attr.setValue("1");
            user.setAttributeNode(attr);

            //Email elements
            Element MailElement = doc.createElement("Email");
            MailElement.appendChild(doc.createTextNode(email));
            user.appendChild(MailElement);

            //Name elements
            Element NameElement = doc.createElement("Name");
            NameElement.appendChild(doc.createTextNode(name));
            user.appendChild(NameElement);

            //Dateofbirth elements
            Element DateElement = doc.createElement("DateOfBirth");
            DateElement.appendChild(doc.createTextNode(dateofbirth));
            user.appendChild(DateElement);

            //Phone elements
            Element PhoneElement = doc.createElement("Phone");
            PhoneElement.appendChild(doc.createTextNode(phone));
            user.appendChild(PhoneElement);
            
            //Address elements
            Element AddElement = doc.createElement("Address");
            AddElement.appendChild(doc.createTextNode(add));
            user.appendChild(AddElement);
            
            //Hash with salt
            String salt = this.RandomString(32);
            String data = salt + pass;
//            KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt.getBytes(), 65536, 128);
//            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            byte[] hash = f.generateSecret(spec).getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes());

            //Passphrase elements
            Element PassElement = doc.createElement("Passphrase");
            PassElement.appendChild(doc.createTextNode(hash.toString()));
            user.appendChild(PassElement);
            
            //Salt elements
            Element SaltElement = doc.createElement("Salt");
            SaltElement.appendChild(doc.createTextNode(salt));
            user.appendChild(SaltElement);
            
            // write the content into xml file
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File("Database.xml"));
            
            transformer.transform(source, result);
        }
    }
    
    public void Log_In (String email, String pass) {
        
    }
    
    public void Update (String email, String name, String dateofbirth, String phone, String add, String pass) throws SAXException, ParserConfigurationException, IOException, NoSuchAlgorithmException, TransformerException, InvalidKeySpecException {
        
        String filepath = "Database.xml";
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
	DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
	Document doc = docBuilder.parse(filepath);
        
        // Get the root element
	Node Data = doc.getFirstChild();
        NodeList nList = doc.getElementsByTagName("User");
        
        for (int i = 0; i < nList.getLength(); i++) 
        {
            Node nNode = nList.item(i);
            
            if (nNode.getNodeType() == Node.ELEMENT_NODE) 
            {
		Element eElement = (Element) nNode;
                if ((eElement.getElementsByTagName("Email").item(0).getTextContent().equals(email)))
                {
                    if (!(eElement.getElementsByTagName("Name").item(0).getTextContent().equals(name)))
                    {
                        eElement.getElementsByTagName("Name").item(0).setTextContent(name);
                    }
                    if (!(eElement.getElementsByTagName("DateOfBirth").item(0).getTextContent().equals(dateofbirth)))
                    {
                        eElement.getElementsByTagName("DateOfBirth").item(0).setTextContent(dateofbirth);
                    }
                    if (!(eElement.getElementsByTagName("Phone").item(0).getTextContent().equals(phone)))
                    {
                        eElement.getElementsByTagName("Phone").item(0).setTextContent(phone);
                    }
                    if (!(eElement.getElementsByTagName("Address").item(0).getTextContent().equals(add)))
                    {
                        eElement.getElementsByTagName("Address").item(0).setTextContent(add);
                    }

                    String tempsalt = eElement.getElementsByTagName("Salt").item(0).getTextContent();
//                    KeySpec tempspec = new PBEKeySpec(pass.toCharArray(), tempsalt.getBytes(), 65536, 128);
//                    SecretKeyFactory tempf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//                    byte[] temphash = tempf.generateSecret(tempspec).getEncoded();
                    String tempdata = tempsalt + pass;
                    MessageDigest tempdigest = MessageDigest.getInstance("SHA-256");
                    byte[] temphash = tempdigest.digest(tempdata.getBytes());
                    
                    if (!(eElement.getElementsByTagName("Passphrase").item(0).getTextContent().equals(temphash.toString())))
                    {
                        //Hash with salt
                        String salt = this.RandomString(32);
                        String data = salt + pass;
//                      KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt.getBytes(), 65536, 128);
//                      SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//                      byte[] hash = f.generateSecret(spec).getEncoded();
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] hash = digest.digest(data.getBytes());

                        eElement.getElementsByTagName("Passphrase").item(0).setTextContent(hash.toString());
                        eElement.getElementsByTagName("Salt").item(0).setTextContent(salt);
                    }
                }
            }
        }
        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(filepath));
        transformer.transform(source, result);
    }
    
    public static void main(String[] args) throws Exception {
        
        User user = new User();
        user.Sign_In("quangdai255@gmail.com", "Đinh Quang Đại", "25/05/1995", "01686871317", "Quận 8, HCM", "Qd25051995!");
        //user.Sign_In("quanghung@gmail.com", "Đinh Quang Hùng", "07/07/1996", "01694437617", "Quận 10, HCM", "1234567");
        //user.Sign_In("quangkhanh@gmail.com", "Đinh Quang Khánh", "19/05/1998", "01681234556", "Quận Thủ Đức, HCM", "123abcd");
        //user.Sign_In("quanganh@gmail.com", "Đinh Quang Khánh", "19/05/1998", "01681234556", "Quận Thủ Đức, HCM", "123abcd");
        //user.Update("quangdai255@gmail.com", "Đinh Quang Đại", "25/05/1995", "01686871317", "Quận 8, HCM", "Qd25051995!");
    }
}