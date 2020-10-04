<h1 align="center">ServerHTTPS</h1>

I'm not perfect so there could be some (a lot) errors.

### Contents
- [General Explainations](#general-explainations)
- [Differences from TLS1.2 and TLS1.3](#differences-from-tls12-and-tls13)
- [JDK](#jdk)
- [Client1 - Print Response](#client1---print-response)
  - [Who/How/Why](#whohowwhy)
- [Server1 - No Sec Layer](#server1---no-sec-layer)
  - [Who/How/Why](#whohowwhy-1)
- [Server2 - Simple SSL](#server2---simple-ssl)
  - [Who/How/Why](#whohowwhy-2)
- [Server3 - SSL with Love](#server3---ssl-with-love)
  - [Who/How/Why](#whohowwhy-3)
- [Ingredients](#ingredients)
- [Handshake](#handshake)
- [Curiosity](#curiosity)
- [Sources](#sources)

## General Explainations

HTTPS is an extension of the Hypertext Transfer Protocol.
The communication protocol is encrypted using Transport Layer Security (TLS) or, **formerly**, Secure Sockets Layer (SSL) is therefore also referred to as HTTP over TLS or HTTP over SSL. 

## Differences from TLS1.2 and TLS1.3

- Removed static RSA
- Removed custom (EC)DHE groups
- Removed compression
- Semi removed (special accommodation fon inline client auth) renegotiation
- Removed non-AEAD ciphers
- Removed simplified resumption

```
Implied for TLS 1.3:
	- Key Exchange / key agreement algorithm: DHE or ECHDE (e.g. not RSA)
	- Authentication mechanism: RSA or DSA or ECDSA
	- Ciphers: AEAD ciphers (e.g. not CBC)
```

## JDK

Java provides several security-based APIs that help out developers to establish secure connections with the client to receive and send messages in an encrypted format:
- Java Secured-Socket Extension ([JSSE](https://en.wikipedia.org/wiki/Java_Secure_Socket_Extension))
- Java Key Store (JKS)
- Java Cryptography Architecture (JCA)
- Java Cryptographic Extension (JCE)
- Java Authentication and Authorization Service (JAAS)
- Public Key Infrastructure (PKI)
- Network Security Services for Java ([JSS](https://www-archive.mozilla.org/projects/security/pki/jss/))

## Client1 - Print Response
### Who/How/Why

It's a code from [here](https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-socket-connection-client-and-server.htm#JSSEC-GUID-AA1C27A1-2CA8-4309-B281-D6199F60E666).

It has to be launched with (or use other method like System.setProperties):
```bash
java -Djavax.net.ssl.trustStore=path_to_samplecacerts_file Client
```
It is used to do a GET request with Java to a Server with SSL.

## Server1 - No Sec Layer
### Who/How/Why

Warm up.

Simple HTTP.

## Server2 - Simple SSL
### Who/How/Why

Code from [here](https://www.pixelstech.net/article/1445603357-A-HTTPS-client-and-HTTPS-server-demo-in-Java).

With some keytool's commands to create keystore, truststore and import cert on client's truststore.

## Server3 - SSL with Love
### Who/How/Why

This is what my mind has created.

What I achieved:
- no use of sun.security libs
- no keytool (use sun's libs) (I'll use openssl)
- cert created and self signed on the fly
- no Bouncy Castle
- no Portecle

## Ingredients

- OpenSSl 1.1.1 (implements support for five TLSv1.3 [cipher suites](#cipher-suite))

| Example of cipher suite | TLS_AES_128_GCM_SHA256 |
| :------- | :------ |
| Protocol | TLS 1.3 |
| Key Exchange | ECHDE or DHE (chosen from client's supported ciphersuites list) |
| Certificate authentication (CA) | RSA, DSA, ECDSA (chosen from client's supported ciphersuites list) |
| Cipher | AES_128_GCM |
| Mac | SHA256 |

## Handshake

Basic full TLS handshake: ([Source](https://www.rfc-editor.org/rfc/rfc8446.html#section-2))
```
       Client                                           Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*       -------->
                                                  ServerHello  ^ Key
                                                 + key_share*  | Exch
                                            + pre_shared_key*  v
                                        {EncryptedExtensions}  ^  Server
                                        {CertificateRequest*}  v  Params
                                               {Certificate*}  ^
                                         {CertificateVerify*}  | Auth
                                                   {Finished}  v
                               <--------  [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}              -------->
       [Application Data]      <------->  [Application Data]
```
    +  Indicates noteworthy extensions sent in the previously noted message.
    *  Indicates optional or situation-dependent messages/extensions that are not always sent.
    {} Indicates messages protected using keys derived from a [sender]_handshake_traffic_secret.
    [] Indicates messages protected using keys derived from [sender]_application_traffic_secret_N.

In practice most clients will use X25519 or P-256 for their initial key_share. For maximum performance it is recommended that servers are configured to support at least those two groups and clients use one of those two for its initial key_share. This is the default case (OpenSSL clients will use X25519).

## Curiosity
- Blowfish
- CCS attack (TLS 1.2)

E.g. of TLS 1.2 cipher suites
> When authentication or key exchange are not indicated <b>tipically</b> you can imply that is RSA

| HexadecimalRappresentation | Protocol_KeyExchange_Auth_Cipher_Mac |
| -------------------------- | ------------------------------------ |
| 0xc02b | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 |
| 0xc02f | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 |
| 0x009e | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 |
| 0xcc14 | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 |
| 0xcc13 | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 |
| 0xc00a | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA |
| 0xc014 | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA |
| 0x0039 | TLS_DHE_RSA_WITH_AES_256_CBC_SHA |
| 0xc009 | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA |
| 0xc013 | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA |
| 0x0033 | TLS_DHE_RSA_WITH_AES_128_CBC_SHA |
| 0x009c | TLS_RSA_WITH_AES_128_GCM_SHA256 |
| 0x0035 | TLS_RSA_WITH_AES_256_CBC_SHA |
| 0x002f | TLS_RSA_WITH_AES_128_CBC_SHA |
| 0x000a | TLS_RSA_WITH_3DES_EDE_CBC_SHA |

## Sources 
> [ sources tagged with {*} are recommended ]
> [ sources tagged with {!} are for visual learner ]
> [ sources tagged with {M} are for Math theory ]

- https://en.wikipedia.org/wiki/Cipher_suite
- {!*}[What is a TLS Cipher Suite?](https://www.youtube.com/watch?v=ZM3tXhPV8v0)
- {!*}[Strong vs. Weak TLS Ciphers](https://www.youtube.com/watch?v=k_C2HcJbgMc)
- {!*}[What Are AEAD Ciphers?](https://www.youtube.com/watch?v=od44W45sCQ4)
- {1} [Difference between pem, csr, key and crt](https://crypto.stackexchange.com/questions/43697/what-is-the-difference-between-pem-csr-key-and-crt)
- [wiki - HTTPS](https://en.wikipedia.org/wiki/HTTPS)
- [Differences from TLS1.2 and TLS1.3](https://www.youtube.com/watch?v=grRi-aFrbSE)
- [TLS 1.3 - RFC 8446](https://tools.ietf.org/html/rfc8446)
- [docs.oracle.com - 15 - api](https://docs.oracle.com/en/java/javase/15/docs/api/index.html)
- [docs.oracle.com - 15 - specs - security](https://docs.oracle.com/en/java/javase/15/docs/specs/security/standard-names.html)
- [Easy start https server - YouTube (2016)](https://www.youtube.com/watch?v=8ptiZlO7ROs)
- [Create & sign SSL/TLS certificates with openssl - YouTube (2020)](https://www.youtube.com/watch?v=7YgaZIFn7mY)
- [A complete overview of SSL/TLS and its cryptographic system - YouTube (2020)](https://www.youtube.com/watch?v=-f4Gbk-U758)
- [LibreSSL](https://www.libressl.org/)
- [OpenSSL manual page](https://man.openbsd.org/openssl.1)
- [OpenSSL manual page (REQ)](https://man.openbsd.org/openssl.1#req)
- [X.509](https://en.wikipedia.org/wiki/X.509)
- [Subject Alternative Name (SAN)](https://en.wikipedia.org/wiki/Subject_Alternative_Name)
- {!}[Transport Layer Security, TLS 1.2 and 1.3 (Explained by Example)](https://www.youtube.com/watch?v=AlE5X1NlHgg)
- {!}[Transport Layer Security 1.3 Explained - TLS Handshake, Key Exchange, TLS Extensions and MITM](https://www.youtube.com/watch?v=ntytZy3i-Jo)
- {!*}[Secret Key Exchange (Diffie-Hellman) - Computerphile](https://www.youtube.com/watch?v=NmM9HA2MQGI)
- {M}[Diffie Hellman -the Mathematics bit- Computerphile](https://www.youtube.com/watch?v=Yjrfm_oRO0w)
- [X25519](https://en.wikipedia.org/wiki/Curve25519)