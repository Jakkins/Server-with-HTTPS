import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLServer {

    private static final String UNICODE_FORMAT = "UTF-8";

    private final SSLServerKeyStore keystore;

    private int port;

    public SSLServer(int port) {
        this.port = port;
        keystore = new SSLServerKeyStore("server.ks");
        Utils.getInstance().exec("./script/generatecert");
        loadServerKeyInKeyStore();
    }

    // PKCS12 = private key + x.509 cert and chain
    private void loadServerKeyInKeyStore() {
        System.out.println("> Init KeyStore");
        try {
            PrivateKey privateKey = Utils.getInstance().privateRSAPemParser("private.pem");

            // Read cert
            InputStream certificateInputStream = new FileInputStream("server.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certificateInputStream);
            java.security.cert.Certificate[] chain = { cert };

            keystore.setKeyEntry("privatepem", privateKey, chain);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static final String[] protocols = new String[] { "TLSv1.2" };
    private static final String[] cipher_suites = new String[] { "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" };
    private static final String message = "Like most of life's problems, this one can be solved with bending!";

    public void start() {
        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("TLSv1.2");
            sc.init(keystore.getKeyManagers(), null, null); // null because I don't ask for client auth
        } catch (Exception e) {
            e.printStackTrace();
        }

        SSLServerSocket sslServerSocket = null;
        try {
            sslServerSocket = (SSLServerSocket) sc.getServerSocketFactory().createServerSocket(port);
        } catch (IOException e1) { e1.printStackTrace(); }
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
                
                //log(s.getHandshakeSession());
                s.startHandshake();   // SSLHandshakeException: No available authentication scheme
                
                
















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

        try {
            sslServerSocket.close();
        } catch (IOException e) { e.printStackTrace(); }
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