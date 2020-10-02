cd C:\\Dev\\Java\\ProvaServer\\bin
rem start cmd /K java -Djavax.net.debug=all HTTPSServer
rem set /P var="Premere un tasto per far partire il client ;)"
rem start cmd /K java -Djavax.net.debug=all HTTPSClient

start cmd /K java HTTPSServer
set /P var="Premere un tasto per far partire il client ;)"
start cmd /K java HTTPSClient