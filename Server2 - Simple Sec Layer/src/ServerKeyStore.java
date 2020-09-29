import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;

import javax.crypto.SecretKey;

public class ServerKeyStore {

    /*
    List of KeyStore Types supported
    - PKCS12
    - JKS, Java Key Store
        - JCEKS
    
    (https://www.computerworld.com/article/2785591/jks-and-jceks--what-s-the-story-.html)
    If you're not using the JCE, then the answer is easy. Your only option
    is to use the JKS keystore. If, however, you have installed the JCE and
    you are using JCE functionality, then your best bet is the JCEKS
    keystore. 
    This keystore provides much stronger protection for stored
    private keys by using Triple DES encryption.
    Migrating up from JKS to JCEKS is relatively easy. You can find
    complete instructions at:
    http://download.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html.
    
    (https://stackoverflow.com/questions/11536848/keystore-type-which-one-to-use)
    - PKCS11, for PKCS#11 libraries, typically for accessing hardware cryptographic tokens, but the Sun provider implementation also supports NSS stores (from Mozilla) through this.
    - BKS, using the BouncyCastle provider (commonly used for Android).
    - Windows-MY/Windows-ROOT, if you want to access the Windows certificate store directly.
    - KeychainStore, if you want to use the OSX keychain directly.
    */

    private KeyStore ks;
    private String path;

    public ServerKeyStore(String path, String type) throws Exception {
        this.path = path;
        if(type == null) ks = KeyStore.getInstance(KeyStore.getDefaultType());
        if(type.equals("PKCS12")) ks = KeyStore.getInstance("PKCS12");
        if(type.equals("JKS")) ks = KeyStore.getInstance("JKS");
        else throw new IllegalArgumentException();
    }

    /*
     * alias = anything you want, a name to identify the entry 
     * certificate = if you use a secret key you don't need this
     */
    public void StoreToKeyStore(SecretKey key, String password) throws Exception {
        ks.load(new FileInputStream(path), password.toCharArray());
        ks.setKeyEntry("aliasPlaceHolder", key, password.toCharArray(), null); // alias, key, password, certificate
        OutputStream writeStream = new FileOutputStream(path);
        ks.store(writeStream, password.toCharArray());

        // writeStream.close(); ??
    }

    public SecretKey ReadFromKeyStore(String password) throws Exception {
        InputStream readStream = new FileInputStream(path);
        ks.load(readStream, password.toCharArray()); // ??
        return (SecretKey) ks.getKey("aliasPlaceHolder", password.toCharArray());
        
        // readStream.close(); ??
    }

}
