import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Main {
    public static void main(String[] args) {

        // TODO use openSSL with exec
        try {
            Process process = Runtime.getRuntime().exec("ls -la");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e1) { e1.printStackTrace(); }
        


        Server server = new Server(8080);
        try { server.start();
        } catch (IOException e) { e.printStackTrace(); }
    }
}
