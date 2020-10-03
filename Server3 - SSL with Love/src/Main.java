public class Main {
    public static void main(String[] args) {
        SSLServer server = new SSLServer(8080);
        server.start();
    }
}
