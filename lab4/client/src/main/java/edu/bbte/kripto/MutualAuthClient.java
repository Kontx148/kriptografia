package edu.bbte.kripto;

import org. slf4j.Logger;
import org. slf4j.LoggerFactory;

import javax.net.ssl.*;
import java. io.*;
import java.nio.charset. StandardCharsets;
import java.nio. file.Files;
import java.nio. file.Path;
import java.security. KeyStore;

/**
 *
 * This client presents its certificate to the server for authentication.
 * It can only connect to servers that trust the ClientCA.
 */
public class MutualAuthClient {

    private static final Logger logger = LoggerFactory.getLogger(MutualAuthClient.class);

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8443;

    // Client's keystore (contains client's private key and certificate)
    private static final String KEYSTORE_PATH = "../certs/client-keystore.p12";
    // Client's truststore (contains CA certificates for server verification)
    private static final String TRUSTSTORE_PATH = "../certs/client-truststore.p12";
    private static final String STORE_PASSWORD = "asd123";

    public static void main(String[] args) {
        logger. info("Starting Mutual Authentication Client...");
        logger.info("This client uses certificate authentication!");

        try {
            // Create SSL context with client certificate
            SSLContext sslContext = createSSLContext();
            SSLSocketFactory factory = sslContext.getSocketFactory();

            logger.info("Connecting to {}: {}...", SERVER_HOST, SERVER_PORT);

            try (SSLSocket socket = (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT)) {

                // Configure SSL parameters
                SSLParameters params = socket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(params);

                // Perform TLS handshake (includes mutual authentication)
                socket.startHandshake();

                logger.info("Mutual authentication successful!");
                logger.info("Protocol: {}", socket. getSession().getProtocol());
                logger.info("Cipher: {}", socket.getSession().getCipherSuite());

                // Display server certificate
                CertificateUtils.printCertificateInfo(socket.getSession());

                // Send HTTP request
                sendRequest(socket);

                // Receive response
                String response = receiveResponse(socket);
                logger.info("Received {} bytes from server", response.length());

                // Save HTML response to file
                saveResponse(response);

            }

        } catch (SSLHandshakeException e) {
            logger. error("Authentication failed!");
            logger.error("Server rejected our certificate: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Connection error: {}", e.getMessage(), e);
        }
    }

    private static SSLContext createSSLContext() throws Exception {
        // Load client's keystore (private key + certificate)
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(Path.of(KEYSTORE_PATH))) {
            keyStore. load(is, STORE_PASSWORD.toCharArray());
        }
        logger. info("Loaded client keystore from {}", KEYSTORE_PATH);

        // Load truststore (contains trusted CA certificates)
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = Files. newInputStream(Path. of(TRUSTSTORE_PATH))) {
            trustStore.load(is, STORE_PASSWORD.toCharArray());
        }
        logger.info("Loaded truststore from {}", TRUSTSTORE_PATH);

        // Initialize key manager with client's certificate
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory. getDefaultAlgorithm()
        );
        kmf. init(keyStore, STORE_PASSWORD. toCharArray());

        // Initialize trust manager with trusted CAs
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }

    private static void sendRequest(SSLSocket socket) throws IOException {
        PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8),
                true
        );

        String request = """
            GET / HTTP/1.1
            Host: %s
            User-Agent: MutualAuthClient/1.0
            Accept: text/html
            Connection: close
            
            """.formatted(SERVER_HOST);

        writer. print(request. replace("\n", "\r\n"));
        writer.flush();
        logger.info("Request sent");
    }

    private static String receiveResponse(SSLSocket socket) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
        );

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader. readLine()) != null) {
            response.append(line).append("\n");
        }
        return response.toString();
    }

    private static void saveResponse(String response) {
        try {
            // Extract HTML body from HTTP response
            String htmlContent = response;
            int bodyStart = response.indexOf("\r\n\r\n");
            if (bodyStart == -1) {
                bodyStart = response.indexOf("\n\n");
            }
            if (bodyStart != -1) {
                htmlContent = response.substring(bodyStart + 4);
            }

            Path outputPath = Path.of("mutual_auth_response.html");
            Files.writeString(outputPath, htmlContent, StandardCharsets.UTF_8);
            logger.info("Response saved to: {}", outputPath.toAbsolutePath());
        } catch (IOException e) {
            logger.error("Failed to save response: {}", e.getMessage());
        }
    }
}