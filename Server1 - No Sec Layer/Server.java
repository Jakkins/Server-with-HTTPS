import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private int port;
    private boolean isServerOn;

    public Server(int port) {
        this.isServerOn = true;
        this.port = port;
    }

    public void start() {
                    
        // create socket
        ServerSocket ss = null;
        try { ss = new ServerSocket(port);
        } catch (IOException e1) { e1.printStackTrace(); }

        // SERVER LOOP
        while(isServerOn) {
            try {
                // Note that the accept() method blocks the current thread until a connection is made.
                Socket s = ss.accept();
                new ServerThread(s).start();
                System.out.println("Connessione accettata, mi rimetto in ascolto");
                
            } catch (IOException e) { e.printStackTrace(); }
        }
        
        try { ss.close();
        } catch (IOException e) { e.printStackTrace(); }
	}

}
