import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;

// lo start viene chiamato sulla classe Server
// lo start chiama il metodo run, ma prima chiama il costruttore

public class ServerThread extends Thread {

    private Socket s;

    public ServerThread(Socket s) {
        this.s = s;
    }

    @Override
    public void run() {
        // Forse questa e' una sessione...
        try {

            // Start handling application content

            // INPUT
            InputStream inputStream = s.getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
            
            String line = null;
            while((line = bufferedReader.readLine()) != null){
                System.out.println("Client : "+line);
                
                // WHY THIS?
                if(line.trim().isEmpty()){
                    break;
                }
            }

            // OUTPUT
            OutputStream outputStream = s.getOutputStream();
            PrintWriter out = new PrintWriter(outputStream);
            
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println("\r\n");
            out.println("<p> Hello world </p>");
            out.flush();
            
            out.close(); // senza il close il client continua ad aspettare l'invio di tutti i dati

            // s.close();
        } catch (Exception e) { e.printStackTrace();}
        
    }

}
