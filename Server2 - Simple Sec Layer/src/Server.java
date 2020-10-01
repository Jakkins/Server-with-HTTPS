import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Server {

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern
            .compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);
    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";
    private static final String UNICODE_FORMAT = "UTF-8";

    private int port;

    public Server(int port) {
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

            System.setProperty("javax.net.ssl.keyStore", "server.ks");
            System.setProperty("javax.net.ssl.keyStorePassword", new String(password));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initKeyStore() {
        // RSAPrivateKey or PrivateKey ?
        System.out.println("> Init KeyStore");
        try {
            char[] password = System.getProperty("javax.net.ssl.keyStorePassword").toCharArray();
            // KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            java.io.FileInputStream fis = new java.io.FileInputStream("server.ks");
            serverKeyStore.load(fis, password);
            // fis.close(); // ???

            // Read and parse and decode private key
            InputStream streamKey = new FileInputStream("private.pem");
            String key = new String(streamKey.readAllBytes());
            // parse
            Matcher privateKeyMatcher = PRIVATE_KEY_PATTERN.matcher(key);
            String parsedPrivateKey = null;
            if (privateKeyMatcher.find()) {
                parsedPrivateKey = privateKeyMatcher.group(1).replace(NEW_LINE, EMPTY).trim();
            }
            streamKey.close();
            if (parsedPrivateKey == null)
                throw new Exception("Invalid private key");
            // decode
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // DSA, EC, DiffieHellman
            byte[] decoded = Base64.getDecoder().decode(parsedPrivateKey); // decode private key in Base64
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));

            // Read cert
            InputStream certificateInputStream = new FileInputStream("server.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certificateInputStream);
            java.security.cert.Certificate[] chain = { cert };

            serverKeyStore.setKeyEntry("privatepem", privateKey, password, chain);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static final String[] protocols = new String[] { "TLSv1.2" };
    private static final String[] cipher_suites = new String[] { "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" };
    private static final String message = "Like most of life's problems, this one can be solved with bending!";

    public void start() throws IOException {

        /*
         * 1. Load Certificate 2. Load KeyStore 3. Load password for KeyStore 4. [Not so
         * optional] load TrustStore 5. Create Secure Socket - Server -
         * javax.net.ssl.SSLServerSocketFactory (this includes authentication keys, peer
         * certificate validation, enabled cipher suites, and the like) -
         * javax.net.ssl.SSLServerSocket - Client - javax.net.ssl.SSLSocketFactory -
         * javax.net.ssl.SSLSocket - Other in-socket - SSLSession
         */

        System.out.println("KeyStore path: " + System.getProperty("javax.net.ssl.keyStore"));
        System.out.println("KeyStore pasw: " + System.getProperty("javax.net.ssl.keyStorePassword"));

        // the fuck is this
        SSLContext sc = null;
        try {
            char[] password = System.getProperty("javax.net.ssl.keyStorePassword").toCharArray();
            KeyStore serverKeyStore = KeyStore.getInstance("PKCS12");
            java.io.FileInputStream fis = new java.io.FileInputStream("server.ks");
            serverKeyStore.load(fis, password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            System.out.println("DEFAULT ALG OF KEYMANAGER: " + KeyManagerFactory.getDefaultAlgorithm());
            System.out.println("KEYMANAGER ACTUAL ALG: " + kmf.getAlgorithm());
            kmf.init(serverKeyStore, password);

            sc = SSLContext.getInstance("TLSv1.2");
            sc.init(kmf.getKeyManagers(), null, null);
        } catch (Exception e) {
            e.printStackTrace();
        }

        SSLServerSocket sslServerSocket = (SSLServerSocket) sc.getServerSocketFactory().createServerSocket(port);
        //sslServerSocket.setNeedClientAuth(false);
        sslServerSocket.setEnabledProtocols(protocols);
        sslServerSocket.setEnabledCipherSuites(sslServerSocket.getSupportedCipherSuites());

        // for( String s : sslServerSocket.getSSLParameters().getProtocols())
        //     System.out.println(s); // TLSv1.3

        // for( String s : sslServerSocket.getSupportedCipherSuites())
        //     System.out.println(s); 
        

        // SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket("localhost", port);
        // socket.setEnabledProtocols(protocols);
        // socket.setEnabledCipherSuites(cipher_suites);

        boolean isServerOn = true;
        while (isServerOn) {
            try {

                // Server in ascolto
                System.out.println("In ascolto");
                SSLSocket s = (SSLSocket) sslServerSocket.accept();
                System.out.println("Connessione accettata");

                // E MO CHE DEVO FARE
                    // Il certificato potrebbe non andare bene
                
                
                s.startHandshake();   // SSLHandshakeException: No available authentication scheme
                log(s.getHandshakeSession());
                
















                InputStream is = new BufferedInputStream(s.getInputStream());
                OutputStream os = new BufferedOutputStream(s.getOutputStream());
                
                byte[] data = new byte[2048];
                int len = is.read(data);
                if (len <= 0) throw new IOException("no data received");
                System.out.printf("server received %d bytes: %s%n", len, new String(data, 0, len));
                os.write(data, 0, len);
                os.flush();

                // TODO Handshake
                // Sessione SSL
                // GET CERTIFICATES

                // PRINT TO CLIENT
                // PrintStream out = new PrintStream(s.getOutputStream());
                // out.println("Hi");
                // out.close();
                // s.close();
            
            } catch (Exception e) { e.printStackTrace(); }
        } // END SERVER LOOP

        sslServerSocket.close();
    }

    private void log(SSLSession session) {
        // LOG
        System.out.println("Peer host: \t" + session.getPeerHost());
        System.out.println("Cipher: \t" + session.getCipherSuite());
        System.out.println("Protocol: \t" + session.getProtocol());
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