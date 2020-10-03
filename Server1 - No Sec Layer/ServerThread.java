import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;

public class ServerThread extends Thread {

    private Socket s;

    public ServerThread(Socket s) {
        this.s = s;
    }

    @Override
    public void run() {
        try {
            // INPUT
            BufferedReader in = new BufferedReader(
                                new InputStreamReader(
                                s.getInputStream()));
            
            String line = null;
            while((line = in.readLine()) != null){
                System.out.println("Client : "+line);
                // if(line.trim().isEmpty()) break; -> should be used ?
            }

            // OUTPUT
            PrintWriter out = new PrintWriter(s.getOutputStream());
            
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println("\r\n");
            out.println("<p> Hello world </p>");
            out.flush();
            
            in.close();
            out.close(); // without close the client continue to wait for all the datas 
            s.close();
        } catch (Exception e) { e.printStackTrace();}
    }

}
