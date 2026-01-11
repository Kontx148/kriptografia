package edu.bbte.kripto;

import org. slf4j.Logger;
import org. slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/*
    1. Irjunk egy kliens alkalmazást, ami TLS-t használva kapcsolódik a https://bnr.ro/Home.aspx címre és egy HTTP GET
    kérést küld a Román Nemzeti Bank szerverének. A szerver által válaszként küldött HTML tartalmat a kliens mentse le egy
    szöveges állományba. A kapcsolat létrejötte után a képernyőre írja a tanúsítvány főbb adatait: verziószám, szériaszám,
    a tanúsító hatóság neve, kibocsátás dátuma, érvényességi ideje, a tanúsítvány alanyának adatai (név, internetes cím(ei))
    , a nyilvános kulcs adatai (a titkosító eljárás típusa, az alany nyilvános kulcsa). Ezeket az adatokat a böngészőben is
    meg lehet nézni (például: https://support.mozilla.org/en-US/kb/secure-website-certificate ,
    de a kliens legyen képes kinyerni és kiírni a főbb adatokat.
*/
public class BNRClient {

    private static final Logger logger = LoggerFactory.getLogger(BNRClient.class);

    private static final String BNR_HOST = "www.bnr.ro";
    private static final int HTTPS_PORT = 443;
    private static final String OUTPUT_FILE = "bnr_response.html";

    public static void main(String[] args) {
        logger.info("Starting BNR TLS Client...");

        // Use Windows-ROOT keystore to access bnr.ro
        // System.setProperty("javax.net.ssl.trustStoreType", "Windows-ROOT");

        // Log relevant system properties
        logger.info("java.home={}", System.getProperty("java.home"));
        logger.info("javax.net.ssl.trustStore={}", System.getProperty("javax.net.ssl.trustStore"));
        logger.info("javax.net.ssl.trustStoreType={}", System.getProperty("javax.net.ssl.trustStoreType"));
        logger.info("javax.net.ssl.keyStore={}", System.getProperty("javax.net.ssl.keyStore"));

        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            // Establish TLS connection to BNR
            logger.info("Connecting to {}:{} via TLS.. .", BNR_HOST, HTTPS_PORT);

            try (SSLSocket socket = (SSLSocket) factory.createSocket(BNR_HOST, HTTPS_PORT)) {

                // Configure TLS parameters for security
                SSLParameters params = socket.getSSLParameters();

                // Enable endpoint identification to verify hostname matches certificate
                params.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(params);

                // Initiate TLS handshake
                socket.startHandshake();
                logger.info("TLS handshake completed successfully!");

                // Get and display the SSL session information
                SSLSession session = socket.getSession();
                logger.info("Protocol: {}", session.getProtocol());
                logger.info("Cipher Suite: {}", session.getCipherSuite());

                // Print detailed certificate information
                CertificateUtils.printCertificateInfo(session);

                // Send HTTP GET request
                sendHttpGetRequest(socket);

                // Receive and save the HTML response
                String htmlContent = receiveHttpResponse(socket);
                saveToFile(htmlContent);

                logger.info("Successfully saved BNR response to {}", OUTPUT_FILE);
            }

        } catch (SSLHandshakeException e) {
            // This exception occurs when certificate validation fails
            logger. error("SSL Handshake failed!  Certificate validation error: {}", e.getMessage());
            logger.error("This could indicate a man-in-the-middle attack or invalid certificate!");
        } catch (Exception e) {
            logger.error("Error connecting to BNR:  {}", e.getMessage(), e);
        }
    }


    private static void sendHttpGetRequest(SSLSocket socket) throws IOException {
        PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8),
                true
        );

        // HTTP/1.1 request with required headers
        String httpRequest = """
            GET / HTTP/1.1
            Host:  %s
            User-Agent: Java-SSL-Client/1.0
            Accept: text/html
            Connection: close
            
            """.formatted(BNR_HOST);

        writer.print(httpRequest.replace("\n", "\r\n"));
        writer.flush();

        logger.info("HTTP GET request sent");
    }


    private static String receiveHttpResponse(SSLSocket socket) throws IOException {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)
        );

        StringBuilder response = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            response.append(line).append("\n");
        }

        logger.info("Received {} bytes of data", response.length());
        return response.toString();
    }


    private static void saveToFile(String content) throws IOException {
        Path outputPath = Path.of(OUTPUT_FILE);
        Files.writeString(outputPath, content, StandardCharsets.UTF_8);
    }
}