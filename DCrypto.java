package DCrypto;
// Thư viện xử lý việc bảo mật
// Bao gồm những chức năng chính sau:
// Mã hóa đối xứng, bất đối xứng, hàm băm, chữ ký điện tử

// 2 thư viện security cho java
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.Base64;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
//import java.lang.String;

public class DCrypto
{
    //IV size tinh theo bytes
    public static byte[] generateRandomIV(int ivSize)
    {
        //Nho chep IV xuong file de luc giai ma bat len
        byte[] iv = new byte[ivSize];	 
        SecureRandom prng = new SecureRandom(); //Tao seed
        prng.nextBytes(iv);
        String initVector = new String(Base64.getEncoder().encode(iv));
        System.out.println("Random IV created: " + initVector);
        return iv;
    }

    public static Key generateSecretKey(String mode, int keySize)
    {
        try 
        {
            //mode = AES hoac blowfish
            KeyGenerator keyGen = KeyGenerator.getInstance(mode);
            keyGen.init(keySize);
            Key key = keyGen.generateKey();
            return key;
        } 

        catch (NoSuchAlgorithmException e) 
        {
            System.out.println("There is no such Algorithm!");
        }

        System.out.println("Failed when create key in" + mode + " with " + keySize + " size");
        return null;
    }

    public static String digestMessage(String mess, String mode)
    {
        if (mess.length() == 0 || mode.length() == 0)
        {
            System.out.println("Empty input strings!");
            return "";
        }
        byte [] plaintext = mess.getBytes();
        String result = "";

        try 
        {
            MessageDigest messDigest = MessageDigest.getInstance(mode);
            //digest message and return
            messDigest.update(plaintext);
            result = new String (messDigest.digest());
        } 
        catch (NoSuchAlgorithmException e) 
        {
                System.out.println("Supported Algorithms: MD2, MD5, SHA-1, SHA-256, SHA-383, SHA-512");
        }
        System.out.println("Message digest: " + result);
        return result;
    }
    
    @SuppressWarnings("empty-statement")
    public static String digestFile(String filename, String algorithm)
    {
        try 
        {
            //Trong bai nay set cung la sha256
            //mode = "SHA-256";
            FileInputStream is = new FileInputStream(filename);
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            DigestInputStream dis = new DigestInputStream(is,digest);
            
            byte[] buffer = new byte[8096];
            while(dis.read(buffer) > -1);
            System.out.println("Hashing completed!\n");
            //dis.getMessageDigest().
            byte[] digestBytes = dis.getMessageDigest().digest();
            //String result = String.format("%064x", new java.math.BigInteger(1, digestBytes));
            String result = new String(Base64.getEncoder().encode(digestBytes));
            return result;
        } 
        catch (FileNotFoundException ex) 
        {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    // Algorithm: <theo_input>
    // Mode: <theo_input>
    // Tham so: Key, IV, Messsge
    public static String symEncryptMessage(String key, String message)
    {
        try 
        {
            //IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            // Hash thanh 32 bytes - 256 bits key
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha.digest(key.getBytes());

            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,"AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] cipherBytes = cipher.doFinal(message.getBytes("UTF-8"));
            String cipherText = new String(Base64.getEncoder().encode(cipherBytes));
            System.out.println("Encrypted Message: " + cipherText);

            return cipherText;	
        }
        catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e)
        {
            System.out.println("NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException");
        } 

        System.out.println("Encrypt failed!!");
        return null; 
    }
    
    public static String symDecryptMessage(String key, String cipherText)
    {
            try 
            {
                //IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                // Hash thanh 32 bytes - 256 bits key
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] keyBytes = sha.digest(key.getBytes());

                SecretKeySpec keySpec = new SecretKeySpec(keyBytes,"AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, keySpec);

                byte[] plainBytes = cipher.doFinal(Base64.getDecoder().decode(cipherText));
                String plainText = new String(plainBytes);
                System.out.println("Decrypted Message: " + plainText);

                return plainText;
            }
            catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e)
            {
                System.out.println("NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException");
            } 
            System.out.println("Decrypt failed!!");
            return null;
    }

    //Input: key, mode ma hoa, padding mode, file inpu, file output
    public static boolean symEncryptFile(String key, String algo, String mode, String padMode, String plainFile,String cipherFile)
    {
        FileInputStream iFile = null; 
        FileOutputStream oFile = null;
        int blockSize;
        try 
        {
            //inputForm = "AES/CBC/PKCS5PADDING";
            String inputForm = algo + '/' + mode + '/' + padMode;
            algo = algo.toUpperCase();
            inputForm = inputForm.toUpperCase();
            System.out.println("Input form: " + inputForm);
            
            int ivSize = 0;
            if(algo.equals("AES"))
                ivSize = 16;
            else if(algo.equals("BLOWFISH"))
                ivSize = 8;
            IvParameterSpec iv = new IvParameterSpec(generateRandomIV(ivSize));
            //MessageDigest md5 = MessageDigest.getInstance("MD5");
            //byte[] keyBytes = md5.digest(key.getBytes("UTF-8"));
            byte [] keyBytes = key.getBytes("UTF-8");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo.toUpperCase());
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.ENCRYPT_MODE,keySpec,iv);

            //Doc va encrypt file
            iFile = new FileInputStream(plainFile);
            oFile = new FileOutputStream(cipherFile);
            
            //Ghi thuat toan ma hoa, mode ma hoa, padding mode va iv
            oFile.write(inputForm.getBytes("UTF-8"));
            oFile.write("|".getBytes("UTF-8"));
            oFile.write(Base64.getEncoder().encode(iv.getIV()));
            oFile.write("\n".getBytes("UTF-8"));
            oFile.flush();
            
            blockSize = 64;
            byte[] blockByte = new byte[blockSize];
            int readBytes=0;
            while ( (readBytes = iFile.read(blockByte)) != -1 )
            {
                byte[] encrypted = cipher.update(blockByte, 0, readBytes);
                if(encrypted != null)
                    oFile.write(encrypted);
            }
            
            byte[] encrypted = cipher.doFinal();
            if(encrypted != null)
                oFile.write(encrypted);
            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Encryption completed!");
            return true;
        } 
        catch (NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public static boolean symDecryptFile(String key, String cipherFile, String plainFile) throws IOException
    {
        //boolean result = false
        FileInputStream iFile = null;
        FileOutputStream oFile = null;
        BufferedReader buffReader = null;
        int blockSize;
        try 
        {
            iFile = new FileInputStream(cipherFile);
            oFile = new FileOutputStream(plainFile);
            buffReader = new BufferedReader(new InputStreamReader(iFile));
            
            //Lan luot la thuat toan, mode cua thuat toan, padding mode va IV
            String[] arg = new String[2];
            String tempLine = buffReader.readLine();
            buffReader.close();
            
            arg = tempLine.split("[|]");
            String inputForm = arg[0].toUpperCase();
            String ivString = arg[1];
            //temp[0] = algo, temp[1] = mode, temp[2] = padMode
            String temp[] = arg[0].split("[/]");
            
            System.out.println("Input form: " + inputForm);
            System.out.println("IV: " + ivString);
            System.out.println("Algorithm: " + temp[0]);
            
            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivString));
            byte[] keyBytes = key.getBytes("UTF-8");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,temp[0].toUpperCase());
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.DECRYPT_MODE,keySpec,iv);
            
            //Cong 2 vi co e ky tu '|'
            int argLen = arg[0].length() + arg[1].length() + 2;
            System.out.println("Check argLen: " + argLen);
            iFile = new FileInputStream(cipherFile);
            iFile.skip(argLen);

            int readBytes = 0;
            blockSize = 64;
            byte[] buffer = new byte[blockSize];
            while ( (readBytes = iFile.read(buffer)) != -1)
            {
                byte[] decrypted = cipher.update(buffer, 0, readBytes);
                if(decrypted != null)
                    oFile.write(decrypted);
            }
            
            byte[] decrypted = cipher.doFinal();
            if(decrypted != null)
                oFile.write(decrypted);
            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Decryption completed!");
            return true;
        } 
        catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        iFile.close();
        oFile.flush();
        oFile.close();
        return false;
    }
    
    //Ma hoa bang session key, sau do ma hoa session key bang public key va nhet vo file
    public static boolean symEncryptFileAdvanced(PublicKey publicKey, String algo, String sessionKeySize, String mode, String padMode, String plainFile, String cipherFile)
    {
        FileInputStream iFile = null; 
        FileOutputStream oFile = null;
        int blockSize;
        try 
        {
            //inputForm = "AES/CBC/PKCS5PADDING";
            String inputForm = algo + '/' + mode + '/' + padMode;
            algo = algo.toUpperCase();
            inputForm = inputForm.toUpperCase();
            System.out.println("Input form: " + inputForm);
            
            //Tao session key
            Key sessionKey = generateSecretKey(algo,Integer.parseInt(sessionKeySize));
            System.out.println("\nSession key: " + keyToString(sessionKey));
            
            int ivSize = 0;
            if(algo.equals("AES"))
                ivSize = 16;
            else if(algo.equals("BLOWFISH"))
                ivSize = 8;
            
            IvParameterSpec iv = new IvParameterSpec(generateRandomIV(ivSize));
            byte [] keyBytes = sessionKey.getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo.toUpperCase());
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.ENCRYPT_MODE,keySpec,iv);

            //Doc va encrypt file
            iFile = new FileInputStream(plainFile);
            oFile = new FileOutputStream(cipherFile);
            
            String encryptedSesionKey = encryptRSAMessage(publicKey, keyToString(sessionKey));
            //encryptRSAMessage           
            
            //Ghi session key da dc ma hoa, thuat toan ma hoa, mode ma hoa, padding mode va iv
            oFile.write(encryptedSesionKey.getBytes("UTF-8"));
            oFile.write("\n".getBytes("UTF-8"));
            oFile.write(inputForm.getBytes("UTF-8"));
            oFile.write("|".getBytes("UTF-8"));
            oFile.write(Base64.getEncoder().encode(iv.getIV()));
            oFile.write("\n".getBytes("UTF-8"));
            oFile.flush();
            
            blockSize = 64;
            byte[] blockByte = new byte[blockSize];
            int readBytes=0;
            while ( (readBytes = iFile.read(blockByte)) != -1 )
            {
                byte[] encrypted = cipher.update(blockByte, 0, readBytes);
                if(encrypted != null)
                    oFile.write(encrypted);
            }
            
            byte[] encrypted = cipher.doFinal();
            if(encrypted != null)
                oFile.write(encrypted);
            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Encryption completed!");
            return true;
        } 
        catch (NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    //Giai ma session key bang private key, sau do giai ma file bang session key
    public static boolean symDecryptFileAdvanced(PrivateKey privateKey, String cipherFile, String plainFile) throws IOException
    {
        //boolean result = false
        FileInputStream iFile = null;
        FileOutputStream oFile = null;
        BufferedReader buffReader = null;
        int blockSize;
        try 
        {
            iFile = new FileInputStream(cipherFile);
            oFile = new FileOutputStream(plainFile);
            buffReader = new BufferedReader(new InputStreamReader(iFile));
            
            //Lan luot doc sessionkey, thuat toan, mode cua thuat toan, padding mode va IV
            String[] arg = new String[2];
            String encryptedSessionKey = buffReader.readLine();
            String tempLine = buffReader.readLine();
            buffReader.close();
            
            //Get tham so len
            arg = tempLine.split("[|]");
            String inputForm = arg[0].toUpperCase();
            String ivString = arg[1];
            //temp[0] = algo, temp[1] = mode, temp[2] = padMode
            String temp[] = arg[0].split("[/]");
            
            System.out.println("Input form: " + inputForm);
            System.out.println("IV: " + ivString);
            System.out.println("Algorithm: " + temp[0]);
            
            IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivString));
            
            //Giai ma session key bang private key
            String sessionKey = decryptRSAMessage(privateKey,encryptedSessionKey);
            Key testKey = stringToKey(sessionKey,temp[0].toUpperCase());
            //testKey.
            //byte[] keyBytes = sessionKey.getBytes("UTF-8");
            byte[] keyBytes = testKey.getEncoded();
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,temp[0].toUpperCase());
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.DECRYPT_MODE,keySpec,iv);
            
            //Cong 3 vi co 2 ky tu '|' va 1 ky tu \n
            //int argLen = arg[0].length() + arg[1].length() + 2;
            int argLen = encryptedSessionKey.length() + arg[0].length() + arg[1].length() + 3;
            System.out.println("Check argLen: " + argLen);
            iFile = new FileInputStream(cipherFile);
            iFile.skip(argLen);

            int readBytes = 0;
            blockSize = 64;
            byte[] buffer = new byte[blockSize];
            while ( (readBytes = iFile.read(buffer)) != -1)
            {
                byte[] decrypted = cipher.update(buffer, 0, readBytes);
                if(decrypted != null)
                    oFile.write(decrypted);
            }
            
            byte[] decrypted = cipher.doFinal();
            if(decrypted != null)
                oFile.write(decrypted);
            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Decryption completed!");
            return true;
        } 
        catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        iFile.close();
        oFile.flush();
        oFile.close();
        return false;
    }
    
    public static boolean RSAEncryptFile(PublicKey pubKey, String plainFile,String cipherFile) throws IOException
    {
        FileInputStream iFile = null; 
        FileOutputStream oFile = null;
        int blockSize;
        try 
        {
            String inputForm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            inputForm = inputForm.toUpperCase();
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.ENCRYPT_MODE,pubKey);
            //System.out.println("Cipher block size:" + cipher.getBlockSize());

            //Doc va encrypt file
            iFile = new FileInputStream(plainFile);
            oFile = new FileOutputStream(cipherFile);
            
            //Ghi thuat toan ma hoa, mode ma hoa, padding mode va iv
//            oFile.write(inputForm.getBytes("UTF-8"));
//            oFile.write("\n".getBytes("UTF-8"));
//            oFile.flush();
            
            //blocksize for OAEP padding
            // Data input size
            blockSize = (((RSAPublicKey)(pubKey)).getModulus().bitLength())/8 - (256/8*2) - 2;
            System.out.println("\nBlock size: " + blockSize);
            byte[] blockByte = new byte[blockSize];
            
            int readBytes=0;
            while ( (readBytes = iFile.read(blockByte)) != -1 )
            {
                byte[] encrypted = cipher.update(blockByte, 0, readBytes);
                encrypted = cipher.doFinal();
                oFile.write(encrypted);
            }

            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Encryption completed!");
            return true;
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) { 
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        iFile.close();
        oFile.flush();
        oFile.close();
        return false;
    }
    
    public static boolean RSADecryptFile(PrivateKey privateKey, String cipherFile, String plainFile)
    {
        //boolean result = false
        FileInputStream iFile = null;
        FileOutputStream oFile = null;
        BufferedReader buffReader = null;
        int blockSize;
        try 
        {
            iFile = new FileInputStream(cipherFile);
            oFile = new FileOutputStream(plainFile);
            
//            buffReader = new BufferedReader(new InputStreamReader(iFile));
//            String inputForm = buffReader.readLine();
//            buffReader.close();
//            System.out.println("\nInput form: " + inputForm);
            
            String inputForm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            Cipher cipher = Cipher.getInstance(inputForm);
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            
            //int argLen = inputForm.length();
            //System.out.println("Check argLen: " + argLen);
            //iFile = new FileInputStream(cipherFile);
            //iFile.skip(argLen + 2);

            int readBytes = 0;
            blockSize = ((RSAPrivateKey)(privateKey)).getModulus().bitLength()/8;
            System.out.println("Input block size: " + blockSize);
            byte[] buffer = new byte[blockSize];
            while ( (readBytes = iFile.read(buffer)) != -1)
            {
                //System.out.println("Read bytes: " + readBytes);
                cipher.update(buffer, 0, readBytes);
                byte[] decrypted = cipher.doFinal();
                oFile.write(decrypted);
                //System.out.println("Decrypted bytes length: " + decrypted.length);
            }

            iFile.close();
            oFile.flush();
            oFile.close();
            
            System.out.println("Decryption completed!");
            return true;
        } 
        catch (FileNotFoundException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public static String encryptRSAMessage(PublicKey key, String message)
    {
        try 
        {
            //String inputForm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] cipherBytes = cipher.doFinal(message.getBytes());
            String cipherText = new String(Base64.getEncoder().encode(cipherBytes));
            System.out.println("Encrypted Message: " + cipherText);

            return cipherText;	
        } 

        catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            System.out.println("NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException");
        } 
        System.out.println("RSA Encryption failed!");
        return null;
    }

    public static String decryptRSAMessage(PrivateKey key, String cipherText)
    {
        try 
        {
                //Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);

                byte[] plainBytes = cipher.doFinal(Base64.getDecoder().decode(cipherText));
                String plainText = new String(plainBytes);
                System.out.println("Decrypted Message: " + plainText);

                return plainText;
        }
        catch (NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e)
        {
            System.out.println("NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException");
        } 

        System.out.println("RSA Encryption failed!");
        return null;
    }

    // Generate 2048-bit RSA Key Pair
    public static KeyPair createRSAKeyPair(int keySize)
    {	
        try 
        {
            System.out.println("Generating RSA Key pair....");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            //  2048 bits
            keyGen.initialize(keySize);
            KeyPair keyPair = keyGen.generateKeyPair();
            System.out.println("RSA key pair has been completed! ^^");
            System.out.println("Private Key: " + keyToString(keyPair.getPrivate()));
            System.out.println("Public Key: " + keyToString(keyPair.getPublic()));
            return keyPair;
        } 
        catch (NoSuchAlgorithmException e) 
        {
            System.out.println("There is no such algorithm exception");
        }
        System.out.println("Failed in generating RSA Key Pair...!");
        return null;
    }

    // ghi xuong file Pem
    public static void exportRSAKeyPair(KeyPair keypair, String filename)
    {
        try
        {
            File keyPairFile = new File(filename + ".pair");

            // File nay chua ca private key va public key
            if (keyPairFile.getParentFile() != null) 
            {
            keyPairFile.getParentFile().mkdirs();
            }
            keyPairFile.createNewFile();

            String temp;
            PrintWriter writer = new PrintWriter(keyPairFile);

            temp = "-----BEGIN RSA PUBLIC KEY-----\n" + keyToString(keypair.getPublic()) +
      "\n-----END RSA PUBLIC KEY-----\n";
            writer.println(temp);

            temp = "-----BEGIN RSA PRIVATE KEY-----\n" + keyToString(keypair.getPrivate()) + 
                            "\n-----END RSA PRIVATE KEY-----\n";
            writer.println(temp);

            writer.close();

        }
        catch (FileNotFoundException e) 
        {
                // TODO Auto-generated catch block
        } 
        catch (IOException e) {
                // TODO Auto-generated catch block
        } 
    }

    public static KeyPair importRSAKeyPair(String filename)
    {
        try 
        {
               File file = new File(filename + ".pair");
               FileReader reader = new FileReader(file);
               BufferedReader bufReader = new BufferedReader(reader);
               bufReader.readLine();

               String strKey = bufReader.readLine();
               PublicKey pubKey = stringToPubKey(strKey);

               bufReader.readLine();
               bufReader.readLine();
               bufReader.readLine();

               strKey = bufReader.readLine();
               PrivateKey pvtKey = stringToPrivateKey(strKey);
               KeyPair keyPair = new KeyPair(pubKey,pvtKey);
               bufReader.close();
               return keyPair;
        } 
        catch (IOException e) 
        {
               // TODO Auto-generated catch block
        }
       return null;
    }

    // ghi xuong file .pub
    public static void exportPublicKey(PublicKey pubKey, String filename)
    {
        try 
        {
            File keyFile = new File(filename + ".pub");

            // File nay chua public key
            if (keyFile.getParentFile() != null) 
            {
                    keyFile.getParentFile().mkdirs();
            }
            keyFile.createNewFile();
            String temp;
            PrintWriter writer = new PrintWriter(keyFile);

            temp = "-----BEGIN RSA PUBLIC KEY-----\n" + keyToString(pubKey) +
      "\n-----END RSA PUBLIC KEY-----\n";
            writer.println(temp);


            writer.close();
        } 
        catch (IOException e) 
        {
        }
    }

    public static PublicKey importPublicKey(String filename)
    {
        try 
        {
            File file = new File(filename);
            FileReader reader = new FileReader(file);
            BufferedReader bufReader = new BufferedReader(reader);

            bufReader.readLine();
            String strKey = bufReader.readLine();
            PublicKey pubKey = stringToPubKey(strKey);

            bufReader.close();
            return pubKey;
        } 
        catch (IOException e) 
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
       return null;
    }

    public static void exportPrivateKey(PrivateKey prvKey, String filename)
    {
        try 
        {
            File keyFile = new File(filename + ".prv");

            // File nay chua public key
            if (keyFile.getParentFile() != null) 
            {
                    keyFile.getParentFile().mkdirs();
            }
            keyFile.createNewFile();
            String temp;
            PrintWriter writer = new PrintWriter(keyFile);

            temp = "-----BEGIN RSA PRIVATE KEY-----\n" + keyToString(prvKey) +
      "\n-----END RSA PRIVATE KEY-----\n";
            writer.println(temp);
            writer.close();
        } 
        catch (IOException e) 
        {
        }
    }

    public static PrivateKey importPrivateKey(String filename)
    {
        try 
        {
            File file = new File(filename);
            FileReader reader = new FileReader(file);
            BufferedReader bufReader = new BufferedReader(reader);

            bufReader.readLine();
            String strKey = bufReader.readLine();
            PrivateKey prvKey = stringToPrivateKey(strKey);

            bufReader.close();
            return prvKey;
        } 
        catch (IOException e) 
        {
        }
       return null;
    }
    
    // ghi xuong file .key
    public static void exportSymmetricKey(Key key, String filename)
    {
        try 
        {
            File keyFile = new File(filename + ".symkey");

            // File nay chua public key
            if (keyFile.getParentFile() != null) 
            {
                    keyFile.getParentFile().mkdirs();
            }
            keyFile.createNewFile();
            String temp;
            PrintWriter writer = new PrintWriter(keyFile);

            temp = "-----BEGIN SYMMETRIC KEY-----\n" + keyToString(key) +
      "\n-----END SYMMETRIC KEY-----\n";
            writer.println(temp);


            writer.close();
            //return null;
        } catch (IOException e) {
            // TODO Auto-generated catch block
        }
    }

    public static Key importSymmetricKey(String filename)
    {
        try 
        {
            File file = new File(filename + ".symkey");
            FileReader reader = new FileReader(file);
            BufferedReader bufReader = new BufferedReader(reader);

            bufReader.readLine();
            String strKey = bufReader.readLine();
            Key key = stringToKey(strKey,"AES");

            bufReader.close();
            return key;
        } 
        catch (IOException e) 
        {
            // TODO Auto-generated catch block
        }
       return null;
    }

    public static String keyToString(Key key)
    {
        byte[] keyBytes = key.getEncoded();
        return new String(Base64.getEncoder().encode(keyBytes));
    }

    public static Key stringToKey(String string, String mode)
    {
        Key key = null;
        byte[] keyBytes;
        try 
        {
                keyBytes = Base64.getDecoder().decode(string.getBytes("UTF-8"));
                SecretKeySpec keySpec = new SecretKeySpec(keyBytes,mode);
                key = keySpec;
        } catch (UnsupportedEncodingException e) 
        {
                // TODO Auto-generated catch block
        }
        return key;
    }

    public static PublicKey stringToPubKey(String strKey)
    {
        byte[] publicBytes = Base64.getDecoder().decode(strKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory;

        try 
        {
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            return pubKey;
        } 
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) 
        {
            // TODO Auto-generated catch block
        }
        return null;
    }

    public static PrivateKey stringToPrivateKey(String strKey)
    {
        byte[] publicBytes = Base64.getDecoder().decode(strKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicBytes);
        KeyFactory keyFactory;

        try {
            keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey prvKey = keyFactory.generatePrivate(keySpec);
            return prvKey;
        } 
        catch (NoSuchAlgorithmException | InvalidKeySpecException e) 
        {

        }
        return null;
    }

    // Tao signature cho message
    public static String signMess(PrivateKey key, String hashMessage)
    {
        try
        {
            byte[] messBytes = hashMessage.getBytes("UTF-8");
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(key);
            sign.update(messBytes);
            byte []signBytes = sign.sign();
            String signature = new String(Base64.getEncoder().encode(signBytes));
            System.out.println("Signature created: " + signature);
            return signature;
        } 
        catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) 
        {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }
    
    public static boolean verifySign(PublicKey key, String fileName, String signature)
    {
        try 
        {
            String hashFile = DCrypto.digestFile(fileName, "SHA-256");
            byte[] originBytes = hashFile.getBytes("UTF-8");
            byte[] signBytes = Base64.getDecoder().decode(signature.getBytes("UTF-8"));
            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(key);
            sign.update(originBytes);
            boolean result =  sign.verify(signBytes);

            if(result == true)
            {
                System.out.println("Signatured verified! ^^");
                return true;
            }
            else
            {
                System.out.println( "Signature isn't verified.... :'(" );
                return false;
            }
        } 
        catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(DCrypto.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
}



