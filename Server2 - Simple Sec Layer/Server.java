import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/*
    > the client initiates a connection
    > receives the server certificate
    > verifies it
    > receives a certificate request from the server and sends its own certificate if it can.

    There is no such thing as a private certificate. 
    The server verifies the certificate: 
        (a) by checking its digital signature
        (b) by forming a trust chain from its signer to a signer it trusts.
*/

public class Server {

    private static final String UNICODE_FORMAT = "UTF-8";

    private int port;
    private boolean isServerOn;
    private KeyStore serveKeyStore;

    public Server(int port) {
        this.isServerOn = true;
        this.port = port;
        
        createServerCertificate(); // Create Certificate

        createServerKeyStore(); // Create Key Store
        
    }

    private void createServerCertificate() {
        
    }

    private void createServerKeyStore() {
        try {
            serveKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            System.out.println(serveKeyStore.getProvider().getName());
            System.out.println(serveKeyStore.getProvider().getInfo());
            System.out.println(serveKeyStore.getProvider().getVersionStr());
            serveKeyStore.load(null); // null if it's a brand new store
            
        } catch (Exception e) { e.printStackTrace(); }
    }

    private static final int keysize = 1024;
    private static final String commonName = "www.test.it";
    private static final String organizationalUnit = "IT";
    private static final String organization = "test";
    private static final String city = "test";
    private static final String state = "test";
    private static final String country = "IT";
    private static final long validity = 1096; // 3 years
    private static final String alias = "tomcat";
    private static final char[] keyPass = "changeit".toCharArray();

    public static final String SIGNING_ALG_ID = "SHA256withRSA";

    public static final String CRL_PEM_NAME = "X509 CRL";
    public static final String CERTIFICATE_PEM_NAME = "CERTIFICATE";

    // Note that using RSA PRIVATE KEY instead of PRIVATE KEY will indicate this is
    // a PKCS1 format instead of a PKCS8.
    public static final String PRIVATE_KEY_PEM_NAME = "RSA PRIVATE KEY";

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
    //             //cert = (X509Certificate) cf.generateCertificate(inStream;
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
        
        ProcessBuilder pb = new ProcessBuilder("ls", "-a", "-l");
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certificateInputStream = new FileInputStream("my-x509-certificate.crt");
        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
        
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