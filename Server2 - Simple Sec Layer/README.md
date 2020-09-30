- [TRY HARD](#try-hard)
- [Let's Go (Start Source)](#lets-go-start-source)
  - [Caption](#caption)
  - [TODO](#todo)
- [OpenSSL](#openssl)
  - [PKCS#1 and PKCS#8 format](#pkcs1-and-pkcs8-format)
  - [PKCS#8 private-key information shall have ASN.1 type](#pkcs8-private-key-information-shall-have-asn1-type)
  - [PKCS#12 or PFX format](#pkcs12-or-pfx-format)
- [Trust Store vs Key Store](#trust-store-vs-key-store)
  - [Caption](#caption-1)
  - [KeyStore](#keystore)
  - [KeyStore's password vs protection parameters](#keystores-password-vs-protection-parameters)
    - [Should the protection param contains the KeyStore password? Idk, maybe yes.](#should-the-protection-param-contains-the-keystore-password-idk-maybe-yes)
- [How to read from file](#how-to-read-from-file)
  - [Read and Parse](#read-and-parse)
    - [PKCS8EncodedKeySpec represents the ASN.1 encoding of a private key](#pkcs8encodedkeyspec-represents-the-asn1-encoding-of-a-private-key)
- [SSLSocket](#sslsocket)
- [Other Things](#other-things)
      - [Warnings](#warnings)
      - [Keystore](#keystore-1)
      - [Client Certificate Authentication](#client-certificate-authentication)
      - [Server Certificates](#server-certificates)
      - [PKI](#pki)
- [Sources](#sources)
- [JDK](#jdk)
- [Certificates](#certificates)
    - [Format of public key certificates](#format-of-public-key-certificates)
- [JSSE](#jsse)
  - [SSLContext supported](#sslcontext-supported)
  - [BHO](#bho)

## TRY HARD

What I want to do:
- try to not use sun (Oracle) lib
- no keytool (use sun lib)
- cert created and self signed on the fly
- no Bouncy Castle
- No Portecle

## Let's Go ([Start Source](https://www.youtube.com/watch?v=T4Df5_cojAs))

### Caption
- CA = Certificate Authority
- CSR = Certificate signing request

### TODO
- Set Up Server
  1. Generate Key-Pair
  2. Extract Public Key
  3. Generate CSR File
     - **To sign the CSR the server can**:
       - Self-signed his own CSR (use its private key to self-sign the CSR)
       - Ask to a Certificate Authority to sign its certificate
         1. send the CSR to a CA
         2. The CA sign the certificate with it's private key
            - Now anyone who has the public key of the CA can verify who really signed
  4. Set Up SSLSocket

- Exchange (TLS1.2??)
   1. Client ask for www.youtube.com
   2. DNS request
   3. The server DNS resolve the name to an IP address
   4. youtube server will send a chain of certs that contain the public keys and for example one is **signed by Google _CA_**
   5. client will check the certificate and his signing CA: if the client know the CA's public key will decrypt the cert and read the information
   6. now the client trust the server and creates a secret key that will be encrypted with the youtube's server public key and will send it to the server
   7. youtube receive the encrypted key, so it'll decrypt it with its private key to gain the secret key
   8. the client and the server are the only ones to know about that secret key

<p> <img src="./images/HTTPSExchange.png" width="1200"> </p>

## OpenSSL

- [Master Source](https://www.openssl.org/docs/)
- [Source 0](https://adamtheautomator.com/install-openssl-powershell/)
- [Source 1 - differences between PEM, DER, P7B/PKCS#7, PFX/PKCS#12 certificates](https://myonlineusb.wordpress.com/2011/06/19/what-are-the-differences-between-pem-der-p7bpkcs7-pfxpkcs12-certificates/)
  - A Windows Server uses .pfx files
  - An Apache Server uses .crt, .cer files
  - Only way to tell the difference between PEM .cer and DER .cer is to open the file in a Text editor and look for the BEGIN/END statements.
- [Source 2](http://www.herongyang.com/Cryptography/keytool-Import-Key-What-Is-PKCS-8.html)
- [Source 3 - Importing PEM certificate into Java KeyStore programmatically](https://stackoverflow.com/questions/51352762/importing-pem-certificate-into-java-keystore-programmatically)
- [Util 0](https://www.sslshopper.com/)

```
PEM Format
It is the most common format that Certificate Authorities issue certificates in. 
It contains the ‘—–BEGIN CERTIFICATE—–” and “—–END CERTIFICATE—–” statements.
Several PEM certificates and even the Private key can be included in one file, one below the other. 
But most platforms(eg:- Apache) expects the certificates and Private key to be in separate files.
> They are Base64 encoded ACII files
> They have extensions such as .pem, .crt, .cer, .key
> Apache and similar servers uses PEM format certificates

DER Format
It is a Binary form of ASCII PEM format certificate. 
All types of Certificates & Private Keys can be encoded in DER format
> They are Binary format files
> They have extensions .cer & .der
> DER is typically used in Java platform

P7B/PKCS#7
They contain “—–BEGIN PKCS—–” & “—–END PKCS7—–” statements. 
It can contain only Certificates & Chain certificates but not the Private key.
> They are Base64 encoded ASCII files
> They have extensions .p7b, .p7c
> Several platforms supports it. eg:- Windows OS, Java Tomcat
```
```
PKCS#8
Available as rfc5208 on the other hand is a standard for handling private keys for all algorithms, not just RSA.
Since most systems today need to support multiple algorithms, and wish to be able to adapt to new algorithms as they are developed, PKCS8 is preferred for private keys, and a similar any-algorithm scheme defined by X.509 for public keys. Although PKCS12/PFX is often preferred to both.
When writing a private key in PKCS#8 format in a file, it needs to stored in either DER encoding or PEM encoding. 
> contains a single private key
> can be encrypted to protect the private key
```
**openssl private key format is specified in PKCS#1 as the RSAPrivateKey ASN.1 structure. It is not compatible with java's PKCS8EncodedKeySpec, which is based on the SubjectPublicKeyInfo ASN.1 structure.**
```
PFX/PKCS#12
They are used for storing the Server certificate, any Intermediate certificates & Private key in one encryptable file.
> They are Binary format files
> They have extensions .pfx, .p12
> Typically used on Windows OS to import and export certificates and Private keys
```

### [PKCS#1 and PKCS#8 format](https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key)

```bash
#!/bin/bash
# Gen Private K
openssl genrsa -out private.key 2048
# Extract Public K
openssl rsa -in private.key -pubout -out public.key
# Gen CSR
openssl req -new -key private.key -out server.csr -subj "/C=IT/ST=Italy/L=The Brands/O=Mosciolo Task Force/OU=SFC/CN=jakkins.who/emailAddress=no"
# Self Sign CSR
openssl x509 -in server.csr -out server.crt -req -signkey private.key
```
OR
```java
// or ProcessBuilder pb = new ProcessBuilder("ls", "-a", "-l");
private void createServerCertificate() {
  // Generate Private Key
  CommandLauncher.getInstance().exec("openssl genrsa -out private.key 2048");
  // Extract Public Key
  CommandLauncher.getInstance().exec("openssl rsa -in private.key -pubout -out public.key");
  // Generate CSR
  CommandLauncher.getInstance().exec("openssl req -new -key private.key -out server.csr -subj \"/C=IT/ST=Italy/L=The Brands/O=Mosciolo Task Force/OU=SFC/CN=jakkins.who/emailAddress=no\"");
  // Self Sign CSR
  CommandLauncher.getInstance().exec("openssl x509 -in server.csr -out server.crt -req -signkey private.key");
}
```

### PKCS#8 private-key information shall have ASN.1 type 

### PKCS#12 or PFX format

**PKCS#12 = (bundle of) private key + server certificate and any intermediate certificates**

**PFX files are usually found with the extensions .pfx and .p12**

```bash
#!/bin/bash
# Create PFX
openssl pkcs12 -inkey private.key -in server.crt -export -out crt.pfx

Breaking down the command:
  openssl               : the command for executing OpenSSL
  pkcs12                : the file utility for PKCS#12 files in OpenSSL
  -export -out crt.pfx  : export and save the PFX file as crt.pfx
  -inkey private.key    : use the private key file private.key as the private key to combine with the certificate.
  -in server.crt        : use server.crt as the certificate the private key will be combined with.
  -certfile more.crt    : This is optional, this is if you have any additional certificates you would like to include in the PFX file.
```

## [Trust Store vs Key Store](https://stackoverflow.com/questions/6340918/trust-store-vs-key-store-creating-with-keytool/6341566#6341566)

### Caption

- KeyStore
  - come in various formats and are not even necessarily file
  - determines the authentication credentials to send to the remote host
  - contains your private keys and certificates (**like a PKCS#12**)
- TrustStore
  - determines the remote authentication credentials which should be trusted
  - contains CA certificates to trust
- keytool
  - a tool to perform various operations on KeyStore and TrustStore (import/export/list/...)

```
The javax.net.ssl.keyStore and javax.net.ssl.trustStore parameters are the default parameters used to build KeyManagers and TrustManagers (respectively), then used to build an SSLContext which essentially contains the SSL/TLS settings to use when making an SSL/TLS connection via an SSLSocketFactory or an SSLEngine.

In some cases, they can be one and the same store, although it's often better practice to use distinct stores 
```

### [KeyStore](https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html)

- KeyStore's password is used to
  - load the keystore
  - protect the private key entry
  - protect the secret key entry
  - store the keystore

different passwords or other protection parameters may also be used. 

### KeyStore's password vs protection parameters

[Source](https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.ProtectionParameter.html)
```
The information stored in a ProtectionParameter object protects the contents of a keystore. 
For example, protection parameters may be used to check the integrity of keystore data, 
or to protect the confidentiality of sensitive keystore data (such as a PrivateKey).
```
```java
// Doc
java.security.KeyStore.setKeyEntry(String alias, byte[] key, Certificate[] chain)
java.security.KeyStore.setKeyEntry(String alias, Key key, char[] password, Certificate[] chain)

java.security.KeyStore.setEntry(String alias, Entry entry, ProtectionParameter protParam)
java.security.KeyStore.setCertificateEntry(String alias, Certificate cert)

java.security.KeyStore.store(OutputStream stream, char[] password) // to save the KeyStore
```
#### Should the protection param contains the KeyStore password? Idk, maybe yes.
```java
// Example
KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);

// Example secret key
javax.crypto.SecretKey mySecretKey = getSecretKey();
KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(mySecretKey);
serverKeyStore.setKeyEntry("secretKeyAlias", skEntry, null);
```
```
KeyStore.setKeyEntry usage:
private key + certificate (like PKCS#12)
secret key + null
```

## How to read from file

```java
File file = new File("private.key");
byte[] encoded = Files.readAllBytes(file.toPath());

// OR

InputStream privateKey = new FileInputStream("private.key");
byte[] encoded = privateKey.readAllBytes();
```

### Read and Parse

```java
public class KeyFormat {

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern
            .compile("-----BEGIN PRIVATE KEY-----(.*?)-----END PRIVATE KEY-----", Pattern.DOTALL);
    private static final String NEW_LINE = "\n";
    private static final String EMPTY = "";

    public static void main(String[] args) {
        try {
            InputStream streamKey = new FileInputStream("private.pem");
            String key = new String(streamKey.readAllBytes());
            Matcher privateKeyMatcher = PRIVATE_KEY_PATTERN.matcher(key);
            if (privateKeyMatcher.find()) {
                String parsedPrivateKey = privateKeyMatcher.group(1).replace(NEW_LINE, EMPTY).trim();
                //System.out.println(parsedPrivateKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                byte[] decoded = Base64.getDecoder().decode(parsedPrivateKey); // decode private key in Base64
                PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
            }
        } catch (Exception e) { e.printStackTrace(); }
    }
}
```

#### PKCS8EncodedKeySpec represents the ASN.1 encoding of a private key

## SSLSocket

[Master Source](https://gist.github.com/artem-smotrakov/bd14e4bde4d7238f7e5ab12c697a86a3)




























---

## Other Things

##### Warnings

[try harder](https://stackoverflow.com/questions/61535731/replacement-for-all-sun-security-package)

[open source partial replacement](https://stackoverflow.com/questions/29622811/open-source-replacement-for-sun-security-rsa-rsapublickeyimpl)

[source](https://stackoverflow.com/questions/28603005/replace-classes-from-sun-security-packages)

[more](https://stackoverflow.com/questions/29060064/sun-security-x509-certandkeygen-and-sun-security-pkcs-pkcs10-missing-in-jdk8)
```
Q: replace classes from sun.security.* packages

(BAD, TRY TO AVOID THIS)
A: There aren't any equivalents in the JDK8 public API. 
You should switch to the BouncyCastle API instead. 
```
Actually BouncyCastle is still using some sun.security classes... [source](https://coderanch.com/t/570343/engineering/Alternatives-sun-security)

But if you want to use BC [link...](https://stackoverflow.com/questions/14930381/generating-x509-certificate-using-bouncy-castle-java/26782357#26782357)

- NO SHA1, use SHA256
- The Certificate Authority has key-pair
- When you install a SO some certificate are already installed

##### Keystore
"Is a binary file that contains a set of private keys. You must keep your keystore in a safe and secure place."
 - several keystores specific to each client.
 - one keystore to manage all your client certificates, that will be identified by an alias.

##### Client Certificate Authentication
"At the start of a SSL or TLS session, the server (**if configured to do so**) may require the client application to submit a client certificate for authentication. Upon receiving the certificate, the server would then use it to identify the certificate's source and determine whether the client should be allowed access"
  - A client certificate, on the other hand, is sent from the client to the server at the start of a session and is used by the server to authenticate the client. 

##### Server Certificates
"A server certificate is sent from the server to the client at the start of a session and is used by the client to authenticate the server"
  - Of the two, server certificates are more commonly used. In fact, it's integral to every SSL or TLS session. Client certificates are not. They're rarely used because:

##### PKI
A public key infrastructure (PKI) consists of:
  - A certificate authority (CA) that stores, issues and signs the digital certificates;
  - A registration authority (RA) which verifies the identity of entities requesting their digital certificates to be stored at the CA; (check client certs)
  - A central directory—i.e., a secure location in which keys are stored and indexed; (KeyStore)
  - A certificate management system managing things like the access to stored certificates or the delivery of the certificates to be issued; (registration system, login system, things like that)
  - A certificate policy stating the PKI's requirements concerning its procedures. Its purpose is to allow outsiders to analyze the PKI's trustworthiness. (dunno)

## Sources

Recommended:
- [Java Security Overview](https://www.baeldung.com/java-security-overview)
- [I'm starting to hate keytool](https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores)
- [Some Caption](https://alvinalexander.com/java/java-keytool-keystore-certificates/)
- [Caption](https://www.jscape.com/blog/client-certificate-authentication)
- [How to Create, Write to and Read a Keystore File Using Java (Simple)](https://www.youtube.com/watch?v=qWKwuHgWwtk) (2020/05/26)
- [Why Developers Should Not Write Programs That Call 'sun' Packages](https://www.oracle.com/java/technologies/faq-sun-packages.html)
- [OpenSSL](https://github.com/openssl)

Other:
- [baeldung.com/java-ssl](https://www.baeldung.com/java-ssl)
- docs oracle com:
  - [Sec documentation index](https://docs.oracle.com/javase/8/docs/technotes/guides/security/index.html)
    - [SSLContext](https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SSLContext)
    - [JSSE](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLOverview)
- [God Source](http://www.java2s.com/Tutorial/Java/0490__Security/Catalog0490__Security.htm)
  - [hint to use SSLServerSocketFactory](http://www.java2s.com/Tutorial/Java/0490__Security/UseSSLServerSocketFactorytocreateaSSLServer.htm)

Certificate:
- [1](https://www.pixelstech.net/article/1406724116-Generate-certificate-in-Java----Self-signed-certificate)
- [2](https://zoltanaltfatter.com/2016/04/30/soap-over-https-with-client-certificate-authentication/)
- [Certificates & Android Version of SSLServerSocket](https://gpotter2.github.io/tutos/en/sslsockets)
  - [Porte clé - github](https://github.com/scop/portecle)
- [java.security.cert.X509Certificate - lot of example](http://www.javased.com/index.php?api=java.security.cert.X509Certificate)
- [How to generate, sign and import SSL certificate from Java [duplicate]](https://stackoverflow.com/questions/4634124/how-to-generate-sign-and-import-ssl-certificate-from-java)

## JDK

Java provides several security-based APIs that help out developers to establish secure connections with the client to receive and send messages in an encrypted format:
- Java Secured-Socket Extension ([JSSE](https://en.wikipedia.org/wiki/Java_Secure_Socket_Extension))
- Java Key Store (JKS)
- Java Cryptography Architecture (JCA)
- Java Cryptographic Extension (JCE)
- Java Authentication and Authorization Service (JAAS)
- Public Key Infrastructure (PKI)
- Network Security Services for Java ([JSS](https://www-archive.mozilla.org/projects/security/pki/jss/))

## Certificates

Bouncy Castle JSSE provider or sun.security or keytool or:
- FileInputStream
- KeyStore
- TrustStore
- KeyPairGenerator
- KeyPair
- TrustManagerFactory
- SSLContext
- KeyManagerFactory
- X509KeyManager
- X509Certificate
- HttpsUrlConnectionMessageSender

Keytool, Porteclé, easy-rsa...

```java
/*
  Providers:
    - SUN
    - AndroidKeyStore
  
  List of KeyStore Types supported (I think these are the type supported by the SUN provider version 14)
    - JKS / BKS (Android)
    - PKCS12 (.p12)
    - JCEKS
    
    (https://stackoverflow.com/questions/11536848/keystore-type-which-one-to-use)
    - PKCS11, for PKCS#11 libraries, typically for accessing hardware cryptographic tokens, but the Sun provider implementation also supports NSS stores (from Mozilla) through this.
    - BKS, using the BouncyCastle provider (commonly used for Android).
    - Windows-MY/Windows-ROOT, if you want to access the Windows certificate store directly.
    - KeychainStore, if you want to use the OSX keychain directly.
*/
KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
// OR
KeyStore keyStore = KeyStore.getInstance("JKS");
// OR
KeyStore keyStore = KeyStore.getInstance("PKCS12");
// OR
KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

System.out.println(keyStore.getProvider().getName());
System.out.println(keyStore.getProvider().getInfo());
System.out.println(keyStore.getProvider().getVersionStr());
```

Assigns the given trusted certificate to the given alias
```java
void setCertificateEntry(String alias, Certificate cert)
```
Saves a keystore Entry under the specified alias.
```java
void setEntry(String alias, KeyStore.Entry entry, KeyStore.ProtectionParameter protParam)
```
Assigns the given key (**that has already been protected**) to the given alias.
```java
void setKeyEntry(String alias, byte[] key, Certificate[] chain)
```
Assigns the given key to the given alias, protecting it with the given password.
```java
void setKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
```

```java
ks.load(null);
```
JKS or PKCS12?

[javax.security.cert.X509Certificate is deprecated. Use CertificateFactory to generate a certificate from raw bytes. There is an example in the javadocs.](https://stackoverflow.com/questions/4414648/javax-security-cert-x509certificate-vs-java-security-cert-x509certificate)

#### Format of public key certificates
Filename extensions for X.509 certificates:
- .pem
- .cer, .crt, .der
- .p7b, .p7c
- .p12 (PKCS12)
- .pfx

Certificate and X509Certficate classes exists both in J2SE and in J2EE.
Imports these.
```java
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
```
Not these.
```java
import javax.security.cert.X509Certificate;
```

[This is](https://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle?answertab=active#tab-top)

**System Process to create and sign certificate**

## [JSSE](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#SSLOverview)

The Java Secure Socket Extension (JSSE) enables secure Internet communications. It provides a framework and an implementation for a Java version of the SSL and TLS protocols and includes functionality for data encryption, server authentication, message integrity, and optional client authentication. Using JSSE, developers can provide for the secure passage of data between a client and a server running any application protocol (such as HTTP, Telnet, or FTP) over TCP/IP.

The JSSE API supports the following security protocols:
- TLS: version 1.0, 1.1, 1.2, **and 1.3 (since JDK 8u261)**
- SSL (Secure Socket Layer): version 3.0

JSSE is a security component of the Java SE platform, and is based on the same design principles found elsewhere in the Java Cryptography Architecture (JCA) framework.

JSSE uses the cryptographic service providers defined by the JCA framework.

<p align="center">
  <img src="./images/jsse-classes-and-interfaces.png">
</p>

**SSLSocket extends the Socket class and provides secure socket.**

**The SSLServerSocketFactory creates SSLServerSocket instances in place of SSLSocket instances.**

```
When using raw SSLSocket and SSLEngine classes, you should always check the peer's credentials before sending any data.
They do not automatically verify that the host name in a URL matches the host name in the peer's credentials.

Since JDK 7, endpoint identification/verification procedures can be handled during SSL/TLS handshaking. See the SSLParameters.getEndpointIdentificationAlgorithm method.

Protocols such as HTTPS (HTTP Over TLS) do require host name verification. Since JDK 7, the HTTPS endpoint identification is enforced during handshaking for HttpsURLConnection by default. See the SSLParameters.getEndpointIdentificationAlgorithm method. Alternatively, applications can use the HostnameVerifier interface to override the default HTTPS host name rules. 
```

### SSLContext supported

- SSL
- SSLv2
- SSLv3
- TLS
- TLSv1
- TLSv1.1
- TLSv1.2
- **and TLSv1.3 (since JDK 8u261)**

```java
SSLContext sslContext1 = SSLContext.getInstance("SSL");
SSLContext sslContext2 = SSLContext.getInstance("SSLv3");
SSLContext sslContext3 = SSLContext.getInstance("TLS");
SSLContext sslContext4 = SSLContext.getInstance("TLSv1");
SSLContext sslContext5 = SSLContext.getInstance("TLSv1.1");
SSLContext sslContext6 = SSLContext.getInstance("TLSv1.2");
```

Tryhard for the TLSv1.3

### BHO

```java
// get user password and file input stream
char[] password = getPassword();
java.io.FileInputStream fis = null;
try {
    fis = new java.io.FileInputStream("keyStoreName");
    keyStore.load(fis, password);
} finally {
    if (fis != null) 
      fis.close();
}
```

