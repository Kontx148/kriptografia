package edu.bbte.kripto;

import org.slf4j. Logger;
import org.slf4j. LoggerFactory;

import javax.net. ssl.*;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file. Files;
import java.nio.file. Path;
import java.security.KeyStore;

public class SimpleClient {

    private static final Logger logger = LoggerFactory.getLogger(SimpleClient.class);

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8443;

    // Only truststore
    private static final String TRUSTSTORE_PATH = "../certs/client-truststore.p12";
    private static final String STORE_PASSWORD = "asd123";

    public static void main(String[] args) {
        logger. info("Starting Simple Client (NO client certificate)...");
        logger.warn("This client has no certificate and should be rejected!");

        try {
            // Create SSL context WITHOUT client certificate
            SSLContext sslContext = createSSLContextWithoutClientCert();
            SSLSocketFactory factory = sslContext.getSocketFactory();

            logger.info("Connecting to {}:{}...", SERVER_HOST, SERVER_PORT);

            try (SSLSocket socket = (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT)) {

                socket.startHandshake();

                // If we reach here, the server accepted the connection - which is NOT expected
                logger.error("Connection succeeded unexpectedly");
            }

        } catch (SocketException e) {
            logger.info("Connection rejected");
            logger.info("Server refused connection: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error: {}", e.getMessage(), e);
        }
    }

    private static SSLContext createSSLContextWithoutClientCert() throws Exception {
        // Only load truststore - NO keystore (no client certificate)
        KeyStore trustStore = KeyStore. getInstance("PKCS12");
        try (InputStream is = Files.newInputStream(Path.of(TRUSTSTORE_PATH))) {
            trustStore.load(is, STORE_PASSWORD. toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );
        tmf.init(trustStore);

        // NO KeyManagers - this means no client certificate will be presented
        SSLContext sslContext = SSLContext. getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        return sslContext;
    }
}