import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
 
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/*
    1. Nel KeyStore e nel TrustStore non ci sono ne certificati ne chiavi
    2. Il keyManagerFactory non da errore nonostante gli passi una password sbagliata
    3. SSLHandshakeException: no cipher suites in common
*/

/*
    1. Posso provare a creare server.jks e test.jks con keytool e vedere cosa succede

    Ho inserito una chiave privata su server.jks e una su test.jks
    e pubblica ??

    Dal Client:
        javax.net.ssl.SSLHandshakeException: Certificate signature validation failed

    Dal Server:
        javax.net.ssl.SSLHandshakeException: Received fatal alert: certificate_unknown
*/

/*
    I had to make the public key of the server trusted by the keystore in the client.
    Then onwards it started working.

    Quindi in pratica devo inserire il certificato del server dentro al TrustStore del client

    NOW WORKS
*/

public class HTTPSServer {

    private static final char[] keyStorePassword = "ciaone".toCharArray();

    private int port = 9999;
    private boolean isServerDone = false;
     
    public static void main(String[] args){

        // provo a creare gli store con keytool
        // createKeyStore();

        HTTPSServer server = new HTTPSServer();
        server.run();
    }
     
    /*
        KEYSTORE
    */
    private static void createKeyStore() {
        try {
            System.out.println("> Generating KeyStore");
            KeyStore serverKeyStore = KeyStore.getInstance("JKS");
            serverKeyStore.load(null, keyStorePassword); // To create an empty keystore pass null as the InputStream argument

            // store away the keystore
            java.io.FileOutputStream fos = null;
            try {
                fos = new java.io.FileOutputStream("server.jks");
                serverKeyStore.store(fos, keyStorePassword);
            } finally {
                if (fos != null)
                    fos.close();
            }

            System.setProperty("javax.net.ssl.keyStore", "server.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", new String(keyStorePassword));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    HTTPSServer() {

    }
     
    HTTPSServer(int port){
        this.port = port;
    }
     
    // Create the and initialize the SSLContext
    private SSLContext createSSLContext(){
        try{
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("server.jks"), keyStorePassword);

            log("Algorithm: " + keyStore.getKey("aliasbhoserver", "ciaone".toCharArray()).getAlgorithm() );
            log("Format: " + keyStore.getKey("aliasbhoserver", "ciaone".toCharArray()).getFormat() );
            keyStore.aliases().asIterator().forEachRemaining( s -> System.out.println(s));
            log("Is Certificate: " + keyStore.isCertificateEntry("aliasbhoserver"));
            log("Is Key Entry: " + keyStore.isKeyEntry("aliasbhoserver"));
            
            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword);
            KeyManager[] km = keyManagerFactory.getKeyManagers();
             
            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();
             
            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km,  tm, null);
             
            return sslContext;
        } catch (Exception ex){
            ex.printStackTrace();
        }
         
        return null;
    }
     
    private void log(Object item) {
        System.out.println(item);
    }

    // Start to run the server
    public void run(){
        SSLContext sslContext = this.createSSLContext();
         
        try{
            // Create server socket factory
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
             
            // Create server socket
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);
             
            System.out.println("SSL server started");
            while(!isServerDone){
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                 
                // Start the server thread
                new ServerThread(sslSocket).start();
            }
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
     
    // Thread handling the socket from client
    static class ServerThread extends Thread {
        private SSLSocket sslSocket = null;
         
        ServerThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;
        }
         
        public void run(){
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());
             
            try{
                // Start handshake
                sslSocket.startHandshake();
                 
                // Get session after the connection is established
                SSLSession sslSession = sslSocket.getSession();
                 
                System.out.println("SSLSession :");
                System.out.println("\tProtocol : "+sslSession.getProtocol());
                System.out.println("\tCipher suite : "+sslSession.getCipherSuite());
                 
                // Start handling application content
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();
                 
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));
                 
                String line = null;
                while((line = bufferedReader.readLine()) != null){
                    System.out.println("Inut : "+line);
                     
                    if(line.trim().isEmpty()){
                        break;
                    }
                }
                 
                // Write data
                printWriter.print("HTTP/1.1 200\r\n");
                printWriter.flush();
                 
                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}