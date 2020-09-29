import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class Server {

    private static final String UNICODE_FORMAT = "UTF-8";

    private int port;
    private boolean isServerOn;

    public Server(int port) {
        this.isServerOn = true;
        this.port = port;
        createServerCertificate();
        createServerKeyStore();
        tryhard();
        // initKeyStore();
    }

    private void tryhard() {
        System.out.println("TRY HARD");
        InputStream pkey;
        try {
            pkey = new FileInputStream("private.pem");
            //PEMParser pemParser = new PEMParser(new FileReader("private.pem"));

            String keyString = 
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPmpKmXAzMliYF" +
            "KyEFHf1X50/ckbDZfZGRa8dLL4Kf3jTd6/OF/vvn+6YDHSfiRq6QiWXJ57MMlMcs" +
            "8z8NDQqaDdW3P99njO2tZAi28r7V2UXn1SYj7i5Z5gOKK40A2hUuiyHZenezGCqn" +
            "eyHLEEZjBtN8Wh+3t+jUUE7zcVngKaY5rnu1e9hz6lpwbKw+NgeJICJQwkHPCOZk" +
            "xh2WXUoyAKwHx9NuXX6OPqSQb25jZ76qlvtQwt6EKuGyu7Y4WfUpEP1u8fJLfo1e" +
            "GNT+80PcIdA5wqKUiKlqubmk+Vqpq3s0uCoH+n9lAn2PScOdVTSukpeZ3tlVDZf2" +
            "3PEyw1fBAgMBAAECggEAUZdhfYp96UY1qSBbOOShdhPN+lU0GTZVqL6gM/d3Mhel" +
            "1XZvXkFphbIMe/rQewjmgJ3PaHvsjcxHP25WYG24tfUsAnpS9iKYIuZG2ogq4mcj" +
            "J0tJUyPACcrxpzMYlrYfTwyVgCC2vKeJ1Ar7rBA4aaD8K0pMXusj0ZXCgcER3pwq" +
            "pqhaRO+G8MES3ikPrxVBl5TYmGcVkq2m3WJL+8xIsN6QB6FBBFZFNfV7lRY06/EQ" +
            "SfUF5Zdc6Z9jWch3TXovamIeKSMM65mVmw2mZE6jkzVG3vNBGUr2gmz+AD8XTwR2" +
            "sB7BmplBlJ0rj9BXDZUwGXCv4yhigPfvG23dasJLBQKBgQDn5W+Nn5Ie2gfdk6UL" +
            "6FUY/o+tGXqxD/LjO1h+w3lxW4etxH5TQW+SGG0a/buEfLms5RBNTvizm8784DpU" +
            "sfp/GM84aGMyx+ug9G0EZlQL3g85oqYhplGCMruMaQg5rDKtbS73GmHsbk7rzGHy" +
            "mC/nHA3D34M+4Ab1gSJXNHIfqwKBgQDlLrxfFvVnlNDPWB/B42QwqEwsxIvgcKed" +
            "LUr6q2jTm7r4N84AacNwUbudzaS3f6v9aAGqux7aa+Ed+FhclfPVEzu7MYCLbUka" +
            "qaqHPIvbzzEM9klRfGw1tLucVJb+/1zRgr5OViLiUXy2y11Y1oJipZWFermwkWhQ" +
            "lp4T+BkqQwKBgD1pmZ1cAQqCm0qm6zK4GLFB2TLyaHezzZM4CDup8OOAZfIy83GB" +
            "Btcd+OcJAzwW++U51JNksqB+RtbZWxlK+Rfnrhk2K+8q2tAJa0WbA+8Qo9+Tn4OR" +
            "1Ewyu1B4EGGVpOYg4Cs4pW5D2ErCGb5xZ15BI7QX4V4pXi5uQHXvwbl5AoGBAOF+" +
            "RHVC/540u+bmjAiXFWMSlDCQChiAf0qU3+sXcAKUfTfwoE2jwlnm8TRou6KYib7A" +
            "8LLtfYPnFQ4J5dbi65BAZkref92vX3hOa6y4E9voVhis0qLMSyPkeZttV0v6MXcq" +
            "rtggxB3tk0m/ek8IcC1jQmScxctGpl50c4CuYQRFAoGAZbnKSW9nOrQEyh4LEnik" +
            "u1ACZvJhxH/khj6oqhV02CgcCYU2hq4/erjqNxb/aI5b4nr7UoEQXgScPOWhWA7L" +
            "Gclb6cAon3+MO1BJm6qKmkjBRAzWqjffreiYGshHWUTfhTs4hjUmzwc88Jkv2eyO" +
            "6feUsvGInQA1t3pt9R2BGeM=";
            System.out.println(keyString);
            

            byte[] encoded = keyString.getBytes();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyString.getBytes());
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    // String keyString = String.join(
    //         "\n",
    //         "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPmpKmXAzMliYF",
    //         "KyEFHf1X50/ckbDZfZGRa8dLL4Kf3jTd6/OF/vvn+6YDHSfiRq6QiWXJ57MMlMcs",
    //         "8z8NDQqaDdW3P99njO2tZAi28r7V2UXn1SYj7i5Z5gOKK40A2hUuiyHZenezGCqn",
    //         "eyHLEEZjBtN8Wh+3t+jUUE7zcVngKaY5rnu1e9hz6lpwbKw+NgeJICJQwkHPCOZk",
    //         "xh2WXUoyAKwHx9NuXX6OPqSQb25jZ76qlvtQwt6EKuGyu7Y4WfUpEP1u8fJLfo1e",
    //         "GNT+80PcIdA5wqKUiKlqubmk+Vqpq3s0uCoH+n9lAn2PScOdVTSukpeZ3tlVDZf2",
    //         "3PEyw1fBAgMBAAECggEAUZdhfYp96UY1qSBbOOShdhPN+lU0GTZVqL6gM/d3Mhel",
    //         "1XZvXkFphbIMe/rQewjmgJ3PaHvsjcxHP25WYG24tfUsAnpS9iKYIuZG2ogq4mcj",
    //         "J0tJUyPACcrxpzMYlrYfTwyVgCC2vKeJ1Ar7rBA4aaD8K0pMXusj0ZXCgcER3pwq",
    //         "pqhaRO+G8MES3ikPrxVBl5TYmGcVkq2m3WJL+8xIsN6QB6FBBFZFNfV7lRY06/EQ",
    //         "SfUF5Zdc6Z9jWch3TXovamIeKSMM65mVmw2mZE6jkzVG3vNBGUr2gmz+AD8XTwR2",
    //         "sB7BmplBlJ0rj9BXDZUwGXCv4yhigPfvG23dasJLBQKBgQDn5W+Nn5Ie2gfdk6UL",
    //         "6FUY/o+tGXqxD/LjO1h+w3lxW4etxH5TQW+SGG0a/buEfLms5RBNTvizm8784DpU",
    //         "sfp/GM84aGMyx+ug9G0EZlQL3g85oqYhplGCMruMaQg5rDKtbS73GmHsbk7rzGHy",
    //         "mC/nHA3D34M+4Ab1gSJXNHIfqwKBgQDlLrxfFvVnlNDPWB/B42QwqEwsxIvgcKed",
    //         "LUr6q2jTm7r4N84AacNwUbudzaS3f6v9aAGqux7aa+Ed+FhclfPVEzu7MYCLbUka",
    //         "qaqHPIvbzzEM9klRfGw1tLucVJb+/1zRgr5OViLiUXy2y11Y1oJipZWFermwkWhQ",
    //         "lp4T+BkqQwKBgD1pmZ1cAQqCm0qm6zK4GLFB2TLyaHezzZM4CDup8OOAZfIy83GB",
    //         "Btcd+OcJAzwW++U51JNksqB+RtbZWxlK+Rfnrhk2K+8q2tAJa0WbA+8Qo9+Tn4OR",
    //         "1Ewyu1B4EGGVpOYg4Cs4pW5D2ErCGb5xZ15BI7QX4V4pXi5uQHXvwbl5AoGBAOF+",
    //         "RHVC/540u+bmjAiXFWMSlDCQChiAf0qU3+sXcAKUfTfwoE2jwlnm8TRou6KYib7A",
    //         "8LLtfYPnFQ4J5dbi65BAZkref92vX3hOa6y4E9voVhis0qLMSyPkeZttV0v6MXcq",
    //         "rtggxB3tk0m/ek8IcC1jQmScxctGpl50c4CuYQRFAoGAZbnKSW9nOrQEyh4LEnik",
    //         "u1ACZvJhxH/khj6oqhV02CgcCYU2hq4/erjqNxb/aI5b4nr7UoEQXgScPOWhWA7L",
    //         "Gclb6cAon3+MO1BJm6qKmkjBRAzWqjffreiYGshHWUTfhTs4hjUmzwc88Jkv2eyO",
    //         "6feUsvGInQA1t3pt9R2BGeM=");
    //         System.out.println(keyString);

    private void createServerCertificate() {
        Utils.getInstance().exec("./script/generatecert");
    }

    private void createServerKeyStore() {
        try {
            System.out.println("> Generating KeyStore");
            char[] password = Utils.getInstance().getPasswordConsole();
            // KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            System.out.println(serverKeyStore.getProvider().getInfo());
            System.out.println(serverKeyStore.getProvider().getVersionStr());

            serverKeyStore.load(null, password); // To create an empty keystore pass null as the InputStream argument

            // store away the keystore
            java.io.FileOutputStream fos = null;
            try {
                fos = new java.io.FileOutputStream("server.ks");
                serverKeyStore.store(fos, password);
            } finally {
                if (fos != null)
                    fos.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initKeyStore() {
        System.out.println("> Saving in KeyStore");
        char[] password = Utils.getInstance().getPasswordConsole();
        try {
            // KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            java.io.FileInputStream fis = new java.io.FileInputStream("server.ks");
            serverKeyStore.load(fis, password);
            // fis.close(); // ???

            // InputStream pkey = new FileInputStream("private.pem");
            // byte[] encoded = pkey.readAllBytes();
            // System.out.println(new String(encoded));

            // KeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            // KeySpec keySpec = new X509EncodedKeySpec(encoded);
            // final KeyFactory keyFactory = KeyFactory.getInstance(matchedAlgorithm);
            // final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
            // final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            System.out.println("Daje");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(null);

            // RSAPrivateKey kp =
            // PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            
            // KeyFactory.getInstance("DiffieHellman").generatePrivate(keySpec);
            // KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            // KeyFactory.getInstance("DSA").generatePrivate(keySpec);
            // KeyFactory.getInstance("EC").generatePrivate(keySpec);

            // PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            System.out.println("Daje");

            InputStream certificateInputStream = new FileInputStream("server.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certificateInputStream);
            java.security.cert.Certificate[] chain = { cert };

            serverKeyStore.setKeyEntry("privatepem", privateKey, password, chain);

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException
                | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    // private void createServerCertificate() {
    //     // (https://stackoverflow.com/questions/12330975/generate-certificate-chain-in-java)
    //     // (https://stackoverflow.com/questions/925377/generate-certificates-public-and-private-keys-with-java)
    //     try {
    //         // Create server public and private keys
    //         KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // KeyPairType or SignatureType(?): RSA, DSA, ECDSA
    //         KeyPair keyPair = kpg.genKeyPair();
            
    //         X509Certificate[] chain = new X509Certificate[1];
    //         //chain[0] = generateX509Certificate();

    //         serveKeyStore.setKeyEntry("server", keyPair.getPrivate(), null, chain);

    //         X509Certificate cert = null;
    //         try { 
    //             CertificateFactory cf = CertificateFactory.getInstance("X509");
    //             //cert = (X509Certificate) cf.generateCertificate(inStream);
    //         } // TODO
    //         catch (Exception ex) { }

    //         // Get an alias for the new keystore entry
    //         String sAlias = cert.getSubjectX500Principal().getName() + cert.getIssuerX500Principal().getName();

    //     } catch (Exception e) { e.printStackTrace(); }
    // }

    public void start() throws IOException {

        /*
         * 1. Load Certificate 1. Create Secure Socket -
         * javax.net.ssl.SSLServerSocketFactory - This includes authentication keys,
         * peer certificate validation, enabled cipher suites, and the like. -
         * javax.net.ssl.SSLSocketFactory
         */
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

        // for(String s : ssf.getDefaultCipherSuites()) System.out.println(s);

        ServerSocket ss = ssf.createServerSocket(port);

        while (isServerOn) {
            try {

                // Server in ascolto
                System.out.println("In ascolto");
                Socket s = ss.accept();
                System.out.println("Connessione accettata");

                // TODO Handshake

                // Sessione SSL
                // GET CERTIFICATES
                SSLSession session = ((SSLSocket) s).getSession();
                // Certificate[] cchain2 = session.getLocalCertificates();
                // for (int i = 0; i < cchain2.length; i++) {
                //     System.out.println(((X509Certificate) cchain2[i]).getSubjectDN());
                // }

                // LOG
                System.out.println("Peer host is " + session.getPeerHost());
                System.out.println("Cipher is " + session.getCipherSuite());
                System.out.println("Protocol is " + session.getProtocol());
                System.out.println("ID is " + new BigInteger(session.getId()));
                System.out.println("Session created in " + session.getCreationTime());
                System.out.println("Session accessed in " + session.getLastAccessedTime());

                // PRINT TO CLIENT
                PrintStream out = new PrintStream(s.getOutputStream());
                out.println("Hi");
                out.close();
                s.close();
            
            } catch (Exception e) { e.printStackTrace(); }
        } // END SERVER LOOP

        ss.close();
    }

    private SecretKey generateKey(String encryptionType) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(encryptionType); // AES
            SecretKey key = keyGenerator.generateKey();
            return key;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] encryptString(String strToEncrypt, SecretKey key, String encryptionType) {
        try {
            byte[] text = strToEncrypt.getBytes(UNICODE_FORMAT);
            Cipher c = Cipher.getInstance(encryptionType);
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedText = c.doFinal(text);
            return encryptedText;
        } catch (Exception e) { e.printStackTrace(); } 
        return null;
    }

    private String decryptString(byte[] byteToDecrypt, SecretKey key, String encryptionType) {
        try {
            Cipher c = Cipher.getInstance(encryptionType);
            c.init(Cipher.DECRYPT_MODE, key);
            byte[] textDecrypted = c.doFinal(byteToDecrypt);
            return new String(textDecrypted);
        } catch (Exception e) { e.printStackTrace(); } 
        return null;
    }

    private X509Certificate generateX509Certificate(String dname, KeyPair pair, int days, String algorithm) 
        throws Exception { 
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new FileInputStream("my-x509-certificate.crt");
        //Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        
        // PrivateKey privkey = pair.getPrivate();
        // X509CertInfo info = new X509CertInfo();
        // X500Name owner = new X500Name(dname);
        return null;
    }
}

// // SecretKey
// SecretKey key = generateKey("AES");

// // try hard
// String txt = "This is an encrypted message.";
// byte[] encryptedText = encryptString(txt, key, "AES");
// for(byte b : encryptedText) 
//     System.out.printf("%2x", b);
// System.out.println();

// // KeyStore
// sks.StoreToKeyStore(key, "ciaone"); // ciaone = password to crypt decrypt the key

// // try hard 2
// SecretKey sk2 = sks.ReadFromKeyStore("ciaone");
// String prova = decryptString(encryptedText, sk2, "AES");
// System.out.println(prova);