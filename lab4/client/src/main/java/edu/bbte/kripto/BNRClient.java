package edu.bbte.kripto;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Logger;

public class BNRClient {

    public static final Logger LOG = Logger.getLogger(BNRClient.class.getName());

    public static void main(String[] args) {
        String urlString = "https://bnr.ro/Home.aspx";
        String outputFile = "bnr_response.html";

        try {
            LOG.info("=== BNR.RO TLS Client ===\n");
            LOG.info("Connecting: " + urlString);

            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // TLS 1.2 vagy újabb beállítása
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            connection.setSSLSocketFactory(sslContext.getSocketFactory());

            // HTTP GET kérés
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0");
            connection.connect();

            // Tanúsítvány lekérése és adatok kiírása
            Certificate[] certs = connection.getServerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate cert = (X509Certificate) certs[0];
                printCertificateInfo(cert);
            }

            // HTTP válasz olvasása
            int responseCode = connection.getResponseCode();
            System.out.println("\n=== HTTP Válasz ===");
            System.out.println("Response Code: " + responseCode);

            // HTML tartalom mentése
            if (responseCode == 200) {
                saveResponse(connection, outputFile);
                System.out.println("HTML tartalom elmentve: " + outputFile);
            } else {
                System.out.println("Hiba: " + responseCode);
            }

            connection.disconnect();

        } catch (Exception e) {
            System.err.println("Hiba: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Tanúsítvány főbb adatainak kiírása
     */
    private static void printCertificateInfo(X509Certificate cert) {
        System.out.println("\n=== Tanúsítvány Adatok ===\n");

        // Verziószám
        System.out.println("Verzió: " + cert.getVersion());

        // Szériaszám
        System.out.println("Szériaszám: " + cert.getSerialNumber().toString(16).toUpperCase());

        // Kibocsátó (Issuer) - Tanúsító hatóság
        System.out.println("Kibocsátó (Issuer): " + cert.getIssuerX500Principal().getName());

        // Alany (Subject) - Tanúsítvány tulajdonosa
        System.out.println("Alany (Subject): " + cert.getSubjectX500Principal().getName());

        // Érvényesség kezdete
        Date notBefore = cert.getNotBefore();
        System.out.println("Érvényesség kezdete: " + notBefore);

        // Érvényesség vége
        Date notAfter = cert.getNotAfter();
        System.out.println("Érvényesség vége: " + notAfter);

        // Nyilvános kulcs típusa és algoritmus
        System.out.println("\n--- Nyilvános Kulcs Adatok ---");
        System.out.println("Algoritmus: " + cert.getPublicKey().getAlgorithm());
        System.out.println("Formátum: " + cert.getPublicKey().getFormat());

        // Nyilvános kulcs
        byte[] publicKeyBytes = cert.getPublicKey().getEncoded();
        System.out.println("Nyilvános kulcs mérete: " + publicKeyBytes.length + " bájt");
        System.out.println("Nyilvános kulcs (első 64 karakter): " +
                bytesToHex(publicKeyBytes).substring(0, Math.min(64, bytesToHex(publicKeyBytes).length())));

        // Aláírás algoritmus
        System.out.println("\nAláírás algoritmus: " + cert.getSigAlgName());

        // Subject Alternative Names (ha van)
        try {
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null && !sans.isEmpty()) {
                System.out.println("\n--- Subject Alternative Names ---");
                for (var san : sans) {
                    System.out.println("  Típus " + san.get(0) + ": " + san.get(1));
                }
            }
        } catch (Exception e) {
            // Nincs SAN
        }
    }

    /**
     * HTTP válasz mentése fájlba
     */
    private static void saveResponse(HttpsURLConnection connection, String filename)
            throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), "UTF-8"));
             BufferedWriter writer = new BufferedWriter(
                     new FileWriter(filename))) {

            String line;
            while ((line = reader.readLine()) != null) {
                writer.write(line);
                writer.newLine();
            }
        }
    }

    /**
     * Bájt tömb hexadecimális stringgé alakítása
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}