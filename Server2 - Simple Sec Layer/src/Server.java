import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
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
import java.security.spec.PKCS8EncodedKeySpec;

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
        initKeyStore();
    }

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
            //KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            java.io.FileInputStream fis = new java.io.FileInputStream("server.ks");
            serverKeyStore.load(fis, password);
            //fis.close(); // ???
            
            InputStream privateKey = new FileInputStream("private.key");
            byte[] encoded = privateKey.readAllBytes();
            System.out.println(new String(encoded));
            // RSAPrivateKey kp = 
            // PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

            InputStream certificateInputStream = new FileInputStream("server.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certificateInputStream);
            java.security.cert.Certificate[] chain = { cert };

            serverKeyStore.setKeyEntry("privateKeyAlias", encoded, chain);

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
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