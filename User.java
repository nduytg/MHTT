/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Users;

import java.io.*;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.security.spec.InvalidKeySpecException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
//import static jdk.nashorn.internal.objects.NativeMath.random;
//import static org.bouncycastle.math.raw.Mod.random;
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
        String salt = this.RandomString(64);
        String data = salt + pass;

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(data.getBytes());
        byte[] md = digest.digest();
        StringBuffer hash = new StringBuffer();
        for (int i = 0; i < md.length; i++) 
        {
            hash.append(Integer.toString((md[i] & 0xff) + 0x100, 16).substring(1));
        }

        //Passphrase elements
        Element PassElement = doc.createElement("Passphrase");
        PassElement.appendChild(doc.createTextNode(hash.toString()));
        user.appendChild(PassElement);

        //Salt elements
        Element SaltElement = doc.createElement("Salt");
        SaltElement.appendChild(doc.createTextNode(salt.toString()));
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
            String salt = this.RandomString(64);
            String data = salt + pass;

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data.getBytes());
            byte[] md = digest.digest();
            StringBuffer hash = new StringBuffer();
            for (int i = 0; i < md.length; i++) 
            {
                hash.append(Integer.toString((md[i] & 0xff) + 0x100, 16).substring(1));
            }
            System.out.println(salt);
            System.out.println(data);
            System.out.println(hash.toString());

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
    
    public boolean Log_In (String email, String pass) throws SAXException, IOException, ParserConfigurationException, NoSuchAlgorithmException {
        
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
                    String salt = eElement.getElementsByTagName("Salt").item(0).getTextContent();
                    String data = salt + pass;
                    
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    digest.update(data.getBytes());
                    byte[] md = digest.digest();
                    StringBuffer hash = new StringBuffer();
                    for (int j = 0; j < md.length; j++) 
                    {
                        hash.append(Integer.toString((md[j] & 0xff) + 0x100, 16).substring(1));
                    }
                    
                    if ((eElement.getElementsByTagName("Passphrase").item(0).getTextContent().equals(hash.toString())))
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
        }
        return false;
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
                    if ((!(eElement.getElementsByTagName("Name").item(0).getTextContent().equals(name))) && (!name.equals("")))
                    {
                        eElement.getElementsByTagName("Name").item(0).setTextContent(name);
                    }
                    if ((!(eElement.getElementsByTagName("DateOfBirth").item(0).getTextContent().equals(dateofbirth))) && (!dateofbirth.equals("")))
                    {
                        eElement.getElementsByTagName("DateOfBirth").item(0).setTextContent(dateofbirth);
                    }
                    if ((!(eElement.getElementsByTagName("Phone").item(0).getTextContent().equals(phone))) && (!phone.equals("")))
                    {
                        eElement.getElementsByTagName("Phone").item(0).setTextContent(phone);
                    }
                    if ((!(eElement.getElementsByTagName("Address").item(0).getTextContent().equals(add))) && (!add.equals("")))
                    {
                        eElement.getElementsByTagName("Address").item(0).setTextContent(add);
                    }
                    
                    if (!pass.equals(""))
                    {
                        String tempsalt = eElement.getElementsByTagName("Salt").item(0).getTextContent();
                        String tempdata = tempsalt + pass;

                        MessageDigest tempdigest = MessageDigest.getInstance("SHA-256");
                        tempdigest.update(tempdata.getBytes());
                        byte[] tempmd = tempdigest.digest();
                        StringBuffer temphash = new StringBuffer();
                        for (int j = 0; j < tempmd.length; j++) 
                        {
                            temphash.append(Integer.toString((tempmd[j] & 0xff) + 0x100, 16).substring(1));
                        }

                        if (!(eElement.getElementsByTagName("Passphrase").item(0).getTextContent().equals(temphash.toString())))
                        {

                            String salt = this.RandomString(64);
                            String data = salt + pass;

                            MessageDigest digest = MessageDigest.getInstance("SHA-256");
                            digest.update(data.getBytes());
                            byte[] md = digest.digest();
                            StringBuffer hash = new StringBuffer();
                            for (int j = 0; j < md.length; j++) 
                            {
                                hash.append(Integer.toString((md[j] & 0xff) + 0x100, 16).substring(1));
                            }

                            eElement.getElementsByTagName("Passphrase").item(0).setTextContent(hash.toString());
                            eElement.getElementsByTagName("Salt").item(0).setTextContent(salt.toString());
                        }
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
    
    public boolean Delete (String email) throws SAXException, IOException, ParserConfigurationException, TransformerException
    {
        boolean check = false;
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
                    Data.removeChild(nNode);
                    check = true;
                }
            }
        }
        
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(filepath));
        transformer.transform(source, result);
        
        return check;
    }
}