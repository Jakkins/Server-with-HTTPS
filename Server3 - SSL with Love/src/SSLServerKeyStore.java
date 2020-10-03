import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

public class SSLServerKeyStore {

    private final KeyStore serverKeyStore;
    private final char[] password;
    private final String path;

    private KeyManagerFactory kmf;

    public SSLServerKeyStore(String path) {
        System.out.println("> Generating KeyStore");
        this.path = path;
        password = Utils.getInstance().getPasswordConsole();
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            System.out.println(ks.getProvider().getInfo());
            // System.out.println(ks.getProvider().getVersionStr()); // 14
            ks.load(null, password); // To create an empty keystore pass null as the InputStream argument
            java.io.FileOutputStream fos = new java.io.FileOutputStream(path);
            ks.store(fos, password); // store away the keystore
            if (fos != null)
                fos.close(); // after all the operation on the keystore, close the stream
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (ks == null) {
                System.err.println("Error on generating KeyStore");
                System.exit(1);
            }
            this.serverKeyStore = ks;
        }
    }

    // If the given key is of type java.security.PrivateKey, it must be accompanied
    // by a certificate chain certifying the corresponding public key.
    // https://docs.oracle.com/en/java/javase/15/docs/api/java.base/java/security/KeyStore.html#setKeyEntry(java.lang.String,java.security.Key,char%5B%5D,java.security.cert.Certificate%5B%5D)
    public void setKeyEntry(String alias, Key key, Certificate[] chain) {
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(path);
            serverKeyStore.load(fis, password);
            serverKeyStore.setKeyEntry(alias, key, password, chain); // PKCS12 = private key + chain (x.509 server cert + chain)
            if (fis != null) fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public KeyManager[] getKeyManagers() {
        if(kmf == null) {
            try {
                kmf = KeyManagerFactory.getInstance("PKIX");
                kmf.init(serverKeyStore, password);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
		return kmf.getKeyManagers();
	}

}
