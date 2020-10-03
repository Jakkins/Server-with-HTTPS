import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLServer {

    private final SSLServerKeyStore keystore;

    private int port;

    public SSLServer(int port) {
        this.port = port;
        keystore = new SSLServerKeyStore("server.ks");
        Utils.getInstance().exec("./script/generatecert");
        loadServerKeyInKey();
    }

    private void loadServerKeyInKey() {
        System.out.println("> Init KeyStore");
        try {
            PrivateKey privateKey = KeyParser.getInstance().parsePKCS8("private.pem");
            InputStream certificateInputStream = new FileInputStream("server.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = cf.generateCertificate(certificateInputStream);
            java.security.cert.Certificate[] chain = { cert };
            keystore.setKeyEntry("privatepem", privateKey, chain);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static final String[] protocols = new String[] { "TLSv1.3" };
    private static final String[] cipher_suites = new String[] { "TLS_AES_128_GCM_SHA256" };

    public void start() {
        SSLContext sc = null;
        SSLServerSocket sslServerSocket = null;
        try {
            sc = SSLContext.getInstance("TLSv1.3");
            sc.init(keystore.getKeyManagers(), null, null); // null because I don't ask for client auth
            sslServerSocket = (SSLServerSocket) sc.getServerSocketFactory().createServerSocket(port);
        } catch (Exception e) {
            e.printStackTrace();
        }
        sslServerSocket.setNeedClientAuth(false);
        sslServerSocket.setEnabledProtocols(protocols);
        sslServerSocket.setEnabledCipherSuites(cipher_suites);

        boolean isServerOn = true;
        while (isServerOn) {
            try {
                System.out.println("> Server Listening");
                SSLSocket s = (SSLSocket) sslServerSocket.accept();
                System.out.println("> Start Handshake");
                s.startHandshake();
                System.out.println("> Connection Accepted");
                
                logSSLSession(s.getSession());

                // INPUT
                InputStream inputStream = s.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String line = null;
                while((line = bufferedReader.readLine()) != null){
                    System.out.println("Client : "+line);
                    if(line.trim().isEmpty()) break;
                }

                // OUTPUT
                OutputStream outputStream = s.getOutputStream();
                PrintWriter out = new PrintWriter(outputStream);
                
                out.println("HTTP/1.1 200 OK");
                out.println("Content-Type: text/html");
                out.println("\r\n");
                out.println("<p> Hello world </p>");
                out.flush();
                out.close(); 

            } catch (Exception e) { e.printStackTrace(); }
        } // END SERVER LOOP

        try {
            sslServerSocket.close();
        } catch (IOException e) { e.printStackTrace(); }
    }

    private void logSSLSession(SSLSession session) {
        System.out.println("Peer host: \t" + session.getPeerHost());
        System.out.println("Cipher: \t" + session.getCipherSuite());
        System.out.println("Protocol: \t" + session.getProtocol());
    }

}

// private SecretKey generateKey(String encryptionType) {
//     try {
//         KeyGenerator keyGenerator = KeyGenerator.getInstance(encryptionType); // AES
//         SecretKey key = keyGenerator.generateKey();
//         return key;
//     } catch (Exception e) {
//         e.printStackTrace();
//     }
//     return null;
// }

// private byte[] encryptString(String strToEncrypt, SecretKey key, String encryptionType) {
//     try {
//         byte[] text = strToEncrypt.getBytes(UNICODE_FORMAT);
//         Cipher c = Cipher.getInstance(encryptionType);
//         c.init(Cipher.ENCRYPT_MODE, key);
//         byte[] encryptedText = c.doFinal(text);
//         return encryptedText;
//     } catch (Exception e) { e.printStackTrace(); } 
//     return null;
// }

// private String decryptString(byte[] byteToDecrypt, SecretKey key, String encryptionType) {
//     try {
//         Cipher c = Cipher.getInstance(encryptionType);
//         c.init(Cipher.DECRYPT_MODE, key);
//         byte[] textDecrypted = c.doFinal(byteToDecrypt);
//         return new String(textDecrypted);
//     } catch (Exception e) { e.printStackTrace(); } 
//     return null;
// }