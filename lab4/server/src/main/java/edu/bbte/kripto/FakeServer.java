package edu.bbte.kripto;

import org.slf4j. Logger;
import org.slf4j. LoggerFactory;

import javax.net. ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file. Files;
import java.nio.file. Path;
import java.security.KeyStore;

/**
 * Task 2: Fake BNR Server with self-signed certificate.
 *
 * This server simulates a man-in-the-middle attack by:
 * 1. Running on localhost with a self-signed certificate claiming to be bnr.ro
 * 2. Serving the previously saved BNR HTML content
 * 3. The client should detect this as a fraudulent server!
 *
 * To test the MITM simulation:
 * 1. Add "127.0.0.1 bnr.ro" to your hosts file
 * 2. Run this server
 * 3. Run the BNRClient - it should fail with a certificate error
 */
public class FakeServer {

    private static final Logger logger = LoggerFactory.getLogger(FakeServer. class);

    private static final int HTTPS_PORT = 443;
    private static final String HTML_FILE = "bnr_response.html";

    // Keystore containing the fake self-signed certificate
    private static final String KEYSTORE_PATH = "../certs/fake-bnr-keystore.p12";
    private static final String KEYSTORE_PASSWORD = "asd";

    public static void main(String[] args) {
        logger.info("Starting Fake BNR Server (MITM Simulation)...");
        logger.warn("This server uses a SELF-SIGNED certificate!");
        logger.warn("A properly configured client should REJECT this connection!");

        try {
            // Load the keystore containing our fake certificate
            KeyStore keyStore = loadKeyStore();

            // Initialize KeyManagerFactory with our keystore
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory. getDefaultAlgorithm()
            );
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Create SSL context with our key managers
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            // Create server socket factory
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

            // Create and configure server socket
            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(HTTPS_PORT)) {

                // Configure TLS settings
                serverSocket. setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

                logger.info("Fake BNR Server listening on port {}", HTTPS_PORT);
                logger.info("Waiting for connections...");

                // Accept and handle connections
                while (true) {
                    try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                        handleClient(clientSocket);
                    } catch (Exception e) {
                        logger.error("Error handling client:  {}", e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            logger. error("Server error: {}", e. getMessage(), e);
        }
    }

    /**
     * Loads the PKCS12 keystore containing the fake certificate.
     */
    private static KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        Path keystorePath = Path.of(KEYSTORE_PATH);
        if (!Files.exists(keystorePath)) {
            throw new FileNotFoundException(
                    "Keystore not found: " + KEYSTORE_PATH +
                            "\nPlease run the certificate generation script first!"
            );
        }

        try (InputStream is = Files.newInputStream(keystorePath)) {
            keyStore.load(is, KEYSTORE_PASSWORD.toCharArray());
        }

        logger.info("Loaded keystore from {}", KEYSTORE_PATH);
        return keyStore;
    }

    /**
     * Handles an incoming client connection.
     */
    private static void handleClient(SSLSocket socket) throws IOException {
        logger.info("Client connected from:  {}", socket.getInetAddress());

        // Read the HTTP request
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
        );

        String line;
        StringBuilder request = new StringBuilder();
        while ((line = reader. readLine()) != null && !line.isEmpty()) {
            request. append(line).append("\n");
        }

        logger.info("Received request:\n{}", request);

        // Read the saved HTML file
        String htmlContent = readHtmlFile();

        // Send HTTP response
        PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8),
                true
        );

        String response = """
            HTTP/1.1 200 OK
            Content-Type: text/html; charset=UTF-8
            Content-Length: %d
            Connection: close
            
            %s""".formatted(htmlContent.length(), htmlContent);

        writer.print(response. replace("\n", "\r\n"));
        writer.flush();

        logger.info("Sent {} bytes of HTML content", htmlContent.length());
    }

    /**
     * Reads the saved BNR HTML file.
     */
    private static String readHtmlFile() {
        try {
            Path htmlPath = Path.of(HTML_FILE);
            if (Files.exists(htmlPath)) {
                return Files.readString(htmlPath, StandardCharsets.UTF_8);
            } else {
                logger.warn("HTML file not found, returning placeholder");
                return "<html><body><h1>Fake BNR Page</h1></body></html>";
            }
        } catch (IOException e) {
            logger.error("Error reading HTML file: {}", e. getMessage());
            return "<html><body><h1>Error loading content</h1></body></html>";
        }
    }
}