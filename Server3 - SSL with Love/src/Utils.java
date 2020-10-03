import java.io.BufferedReader;
import java.io.Console;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        char[] password = null;
        boolean passAreEquals = false;
        do {
            char[] try1 = console.readPassword("Enter Password: ");
            char[] try2 = console.readPassword("Confirm Password: ");
            passAreEquals = java.util.Arrays.equals(try1, try2);
        } while(!passAreEquals);
        
        return password;
    }
    
}