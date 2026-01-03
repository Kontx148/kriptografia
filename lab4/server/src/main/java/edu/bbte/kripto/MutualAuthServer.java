package edu.bbte.kripto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security. cert.X509Certificate;

/**
 * Task 6: Server with Mutual TLS Authentication (mTLS).
 *
 * This server requires clients to present a valid certificate signed by ClientCA.
 * It demonstrates mutual authentication where both server and client verify each other.
 *
 * The server will REJECT connections from clients without proper certificates.
 */
public class MutualAuthServer {

    private static final Logger logger = LoggerFactory.getLogger(MutualAuthServer.class);

    private static final int SERVER_PORT = 8443;
    private static final String HTML_FILE = "bnr_response.html";

    // Server's keystore (contains server's private key and certificate)
    private static final String KEYSTORE_PATH = "../certs/server-keystore.p12";
    // Server's truststore (contains CA certificates for client verification)
    private static final String TRUSTSTORE_PATH = "../certs/server-truststore.p12";
    private static final String STORE_PASSWORD = "asd123";

    public static void main(String[] args) {
        logger. info("Starting Mutual Authentication Server.. .");
        logger.info("This server requires client certificate authentication!");

        try {
            // Create SSL context with mutual authentication
            SSLContext sslContext = createSSLContext();
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(SERVER_PORT)) {

                // CRITICAL: This setting requires client to present a certificate
                serverSocket. setNeedClientAuth(true);

                // Configure allowed TLS protocols
                serverSocket.setEnabledProtocols(new String[]{"TLSv1.2"});

                logger.info("Mutual Auth Server listening on port {}", SERVER_PORT);
                logger.info("Requiring client certificate authentication");
                logger.info("Waiting for connections...");

                while (true) {
                    try {
                        SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                        handleClient(clientSocket);
                    } catch (SSLHandshakeException e) {
                        // This happens when client doesn't have proper certificate
                        logger.warn("Client rejected - Certificate authentication failed:  {}", e.getMessage());
                    } catch (Exception e) {
                        logger.error("Error handling client: {}", e.getMessage());
                    }
                }
            }

        } catch (Exception e) {
            logger.error("Server startup error: {}", e. getMessage(), e);
        }
    }

    /**
     * Creates an SSL context configured for mutual authentication.
     */
    private static SSLContext createSSLContext() throws Exception {
        // Load server's keystore (contains private key + certificate)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(Path.of(KEYSTORE_PATH))) {
            keyStore. load(is, STORE_PASSWORD.toCharArray());
        }
        logger.info("Loaded server keystore from {}", KEYSTORE_PATH);

        // Load truststore (contains CA certificates for client verification)
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(Path.of(TRUSTSTORE_PATH))) {
            trustStore. load(is, STORE_PASSWORD.toCharArray());
        }
        logger. info("Loaded truststore from {}", TRUSTSTORE_PATH);

        // Initialize KeyManagerFactory with server's private key
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory. getDefaultAlgorithm()
        );
        kmf.init(keyStore, STORE_PASSWORD.toCharArray());

        // Initialize TrustManagerFactory with trusted CA certificates
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);

        // Create SSL context with both key and trust managers
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }

    /**
     * Handles an authenticated client connection.
     */
    private static void handleClient(SSLSocket socket) throws IOException {
        logger.info("Client connected from: {}", socket.getInetAddress());

        // Get client's certificate information
        try {
            SSLSession session = socket.getSession();
            X509Certificate clientCert = (X509Certificate) session.getPeerCertificates()[0];
            logger.info("Client authenticated as: {}", clientCert.getSubjectX500Principal().getName());
            logger.info("Certificate issued by: {}", clientCert.getIssuerX500Principal().getName());
        } catch (Exception e) {
            logger.warn("Could not retrieve client certificate details");
        }

        // Read HTTP request
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket. getInputStream(), StandardCharsets.UTF_8)
        );

        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            logger. debug("Request: {}", line);
        }

        // Send HTML response
        String htmlContent = readHtmlFile();
        PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8),
                true
        );

        String response = """
            HTTP/1.1 200 OK
            Content-Type:  text/html; charset=UTF-8
            Content-Length:  %d
            Connection: close
            
            %s""". formatted(htmlContent. length(), htmlContent);

        writer.print(response. replace("\n", "\r\n"));
        writer.flush();

        logger.info("Response sent to authenticated client");
        socket.close();
    }

    private static String readHtmlFile() {
        try {
            Path path = Path.of(HTML_FILE);
            if (Files. exists(path)) {
                return Files. readString(path, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            logger.error("Error reading HTML file: {}", e.getMessage());
        }
        return "<html><body><h1>Secure Content</h1><p>You are authenticated! </p></body></html>";
    }
}