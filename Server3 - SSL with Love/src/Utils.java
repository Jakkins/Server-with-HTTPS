import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

public class Utils {

    private static Utils cl;

    private Utils() {}

    public static Utils getInstance() {
        if (cl == null)
            cl = new Utils();
        return cl;
    }

    public void exec(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) { System.out.println(line); }
        } catch (IOException e1) { e1.printStackTrace(); }
    }

	public char[] getPasswordConsole() {
        Console console = System.console();
        if (console == null) {
            System.out.println("Couldn't get Console instance");
            System.exit(0);
        }
        return console.readPassword("Enter Password: ");
	}
    
}