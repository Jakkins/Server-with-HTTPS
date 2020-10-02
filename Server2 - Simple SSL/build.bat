javac HTTPSClient.java -d .\\bin
javac HTTPSServer.java -d .\\bin

cd C:\\Dev\\Java\\ProvaServer\\bin

echo create server.jks
rem generate key-pair
rem pass = ciaone
keytool -genkey -alias aliasbhoserver -keyalg RSA -keystore "server.jks"
rem keytool -v -list -keystore "server.jks"

echo create test.jks
rem generate key-pair
rem pass = ciaone
keytool -genkey -alias aliasbhoclient -keyalg RSA -keystore "test.jks"

echo generate cert
keytool -export -alias aliasbhoserver -file "cert.cer" -keystore "server.jks"

echo import server's cert in client's truststore
keytool -keystore "test.jks" -importcert -alias aliasbhoserver -file "cert.cer"