package edu.bbte.kripto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSession;
import java. security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util. Collection;
import java. util.List;


public class CertificateUtils {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

    private CertificateUtils() {
    }

    /**
     * Extracts and logs all relevant information from an SSL session's peer certificates.
     *
     * @param session The SSL session containing the peer certificates
     */
    public static void printCertificateInfo(SSLSession session) {
        try {
            // Get the certificate chain from the SSL session
            java.security.cert. Certificate[] certificates = session.getPeerCertificates();

            if (certificates. length == 0) {
                logger. warn("No certificates found in the session");
                return;
            }

            // The first certificate in the chain is the server's certificate
            X509Certificate serverCert = (X509Certificate) certificates[0];
            printX509CertificateDetails(serverCert);

        } catch (Exception e) {
            logger.error("Failed to extract certificate information:  {}", e.getMessage(), e);
        }
    }

    /**
     * Prints detailed information about an X.509 certificate.
     *
     * @param cert The X.509 certificate to analyze
     */
    public static void printX509CertificateDetails(X509Certificate cert) {
        logger.info("===============================================================");
        logger.info("                    CERTIFICATE DETAILS                        ");
        logger.info("===============================================================");

        // Version number
        logger.info("Version: V{}", cert.getVersion());

        // Serial number (unique identifier assigned by the CA)
        logger.info("Serial Number:  {}", cert.getSerialNumber().toString(16).toUpperCase());

        // Certificate Authority (Issuer) information
        logger. info("Issuer (Certificate Authority): {}", cert.getIssuerX500Principal().getName());

        // Validity period
        logger.info("Not Before: {}", cert.getNotBefore());
        logger.info("Not After:  {}", cert.getNotAfter());

        // Subject (certificate owner)
        logger. info("Subject (certificate owner): {}", cert.getSubjectX500Principal().getName());

        // Subject Alternative Names (SANs) - additional domain names
        printSubjectAlternativeNames(cert);

        // Public key information
        printPublicKeyInfo(cert. getPublicKey());

        // Signature algorithm
        logger. info("Signature Algorithm: {}", cert. getSigAlgName());

        logger.info("===============================================================");
    }

    /**
     * Extracts and prints Subject Alternative Names (SANs) from the certificate.
     * SANs can include DNS names, IP addresses, email addresses, etc.
     */
    private static void printSubjectAlternativeNames(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null && ! sans.isEmpty()) {
                logger.info("Subject Alternative Names (Internet Addresses):");
                for (List<?> san : sans) {
                    // SAN type: 0=otherName, 1=rfc822Name, 2=dNSName, 7=iPAddress
                    int type = (Integer) san.get(0);
                    String value = san.get(1).toString();
                    String typeName = switch (type) {
                        case 0 -> "Other Name";
                        case 1 -> "Email";
                        case 2 -> "DNS";
                        case 7 -> "IP Address";
                        default -> "Unknown (" + type + ")";
                    };
                    logger. info("  - {} :  {}", typeName, value);
                }
            }
        } catch (Exception e) {
            logger.debug("No Subject Alternative Names found or error reading them:  {}", e.getMessage());
        }
    }

    /**
     * Prints public key details including algorithm type and key size.
     */
    private static void printPublicKeyInfo(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm();
        logger.info("Public Key Algorithm: {}", algorithm);

        // Determine key size based on algorithm type
        if (publicKey instanceof RSAPublicKey rsaKey) {
            // RSA key - get modulus bit length
            int keySize = rsaKey.getModulus().bitLength();
            logger.info("RSA Key Size:  {} bits", keySize);
            logger.info("RSA Public Exponent: {}", rsaKey.getPublicExponent());
        } else if (publicKey instanceof ECPublicKey ecKey) {
            // Elliptic Curve key - get curve parameters
            int keySize = ecKey.getParams().getOrder().bitLength();
            logger.info("EC Key Size: {} bits", keySize);
            logger.info("EC Curve: {}", ecKey.getParams().toString());
        } else {
            // Other algorithm types
            logger.info("Key Format: {}", publicKey.getFormat());
        }

        // Print the encoded public key in hex format (truncated for readability)
        byte[] encoded = publicKey.getEncoded();
        StringBuilder hexKey = new StringBuilder();
        for (int i = 0; i < Math.min(32, encoded.length); i++) {
            hexKey.append(String.format("%02X", encoded[i]));
        }
        logger.info("Public Key (first 32 bytes): {}...", hexKey);
    }
}