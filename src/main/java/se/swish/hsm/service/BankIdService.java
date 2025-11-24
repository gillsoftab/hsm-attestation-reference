package se.swish.hsm.service;

import lombok.Data;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.math.BigInteger;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class BankIdService {

    private static final Pattern CERT_PATTERN = Pattern.compile(
            "<X509Certificate>([^<]+)</X509Certificate>");

    public BankIdResult verify(String signatureBase64, String ocspBase64) {
        try {
            byte[] xmlBytes = Base64.getDecoder().decode(signatureBase64);
            String xml = new String(xmlBytes, StandardCharsets.UTF_8);

            // Extract all certificates
            List<X509Certificate> certs = extractCertificates(xml);
            if (certs.isEmpty()) {
                return BankIdResult.invalid("No X509Certificate found");
            }

            // Verify certificate chain
            List<String> chainErrors = verifyCertificateChain(certs);

            // User cert is first in chain
            X509Certificate userCert = certs.get(0);
            String subjectDn = userCert.getSubjectX500Principal().getName();

            Instant producedAt = null;
            if (ocspBase64 != null && !ocspBase64.isBlank()) {
                try {
                    byte[] ocspBytes = Base64.getDecoder().decode(ocspBase64);
                    if (!verifyOcspMatchesCertificate(ocspBytes, userCert)) {
                        return BankIdResult.invalid("OCSP response does not match BankID certificate");
                    }
                    producedAt = extractOcspProducedAt(ocspBytes);
                } catch (Exception ignored) {
                }
            }

            // Extract personal number and name from user cert
            String personalNumber = extractDnField(subjectDn, "SERIALNUMBER");
            if (personalNumber == null) {
                personalNumber = extractDnField(subjectDn, "2.5.4.5");
            }
            String name = extractDnField(subjectDn, "CN");

            if (personalNumber == null) {
                return BankIdResult.invalid("No personalNumber in certificate");
            }

            // Extract usrVisibleData (what the user sees and signs)
            String usrVisibleData = extractTagContent(xml, "usrVisibleData");
            if (usrVisibleData != null) {
                usrVisibleData = new String(Base64.getDecoder().decode(usrVisibleData), StandardCharsets.UTF_8);
            }

            // Extract usrNonVisibleData (e.g. hash of agreement or information of a
            // technical nature)
            String usrNonVisibleData = extractTagContent(xml, "usrNonVisibleData");
            if (usrNonVisibleData != null) {
                usrNonVisibleData = new String(Base64.getDecoder().decode(usrNonVisibleData), StandardCharsets.UTF_8);
            }

            // Extract srvInfo/name (Relying Party info - the organization the individual
            // signed with)
            String relyingPartyRaw = extractNestedTagContent(xml, "srvInfo", "name");
            String relyingPartyName = null;
            String relyingPartyOrgNumber = null;
            if (relyingPartyRaw != null) {
                String decoded = new String(Base64.getDecoder().decode(relyingPartyRaw), StandardCharsets.UTF_8);
                relyingPartyName = extractDnField(decoded, "name");
                if (relyingPartyName == null) {
                    relyingPartyName = extractDnField(decoded, "cn");
                }
                relyingPartyOrgNumber = extractDnField(decoded, "serialNumber");
            }
            String signatureTimeRaw = extractTagContent(xml, "signingTime");
            if (signatureTimeRaw == null) {
                signatureTimeRaw = extractNestedTagContent(xml, "bankIdSignedData", "signingTime");
            }
            BankIdResult result = new BankIdResult();
            result.setValid(chainErrors.isEmpty());
            result.setPersonalNumber(personalNumber);
            result.setName(name);
            result.setUsrVisibleData(usrVisibleData);
            result.setUsrNonVisibleData(usrNonVisibleData);
            result.setRelyingPartyName(relyingPartyName);
            result.setRelyingPartyOrgNumber(relyingPartyOrgNumber);
            if (producedAt != null) {
                result.setSignatureTime(producedAt);
            }
            result.setSignatureTime(producedAt);
            result.setCertificateChainValid(chainErrors.isEmpty());
            result.setCertificateChainErrors(chainErrors);
            result.setCertificateCount(certs.size());
            if (!chainErrors.isEmpty()) {
                result.setError("Certificate chain validation failed");
            }

            return result;

        } catch (Exception e) {
            return BankIdResult.invalid("Parse error: " + e.getMessage());
        }
    }

    private List<X509Certificate> extractCertificates(String xml) throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        Matcher matcher = CERT_PATTERN.matcher(xml);
        while (matcher.find()) {
            String certB64 = matcher.group(1).replaceAll("\\s", "");
            byte[] certBytes = Base64.getDecoder().decode(certB64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certBytes));
            certs.add(cert);
        }
        return certs;
    }

    private Instant extractOcspProducedAt(byte[] ocsp) {
        try {
            int pos = 0;
            while (pos < ocsp.length - 20) {
                if (ocsp[pos] == 0x18 && ocsp[pos + 1] == 0x0F) {
                    String time = new String(ocsp, pos + 2, 15, StandardCharsets.US_ASCII);
                    return Instant.parse(time.substring(0, 4) + "-" +
                            time.substring(4, 6) + "-" + time.substring(6, 8) + "T" +
                            time.substring(8, 10) + ":" + time.substring(10, 12) + ":" +
                            time.substring(12, 14) + "Z");
                }
                pos++;
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private boolean verifyOcspMatchesCertificate(byte[] ocsp, X509Certificate userCert) {
        try {
            // OCSP CertID contains serial number
            // Look for serial number in OCSP (tag 0x02 = INTEGER)
            int pos = 0;
            while (pos < ocsp.length - 20) {
                if (ocsp[pos] == 0x02) { // INTEGER tag
                    int len = ocsp[pos + 1] & 0xFF;
                    if (len > 0 && len < 20) {
                        byte[] serialBytes = Arrays.copyOfRange(ocsp, pos + 2, pos + 2 + len);
                        BigInteger ocspSerial = new BigInteger(1, serialBytes);
                        if (ocspSerial.equals(userCert.getSerialNumber())) {
                            return true;
                        }
                    }
                }
                pos++;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private List<String> verifyCertificateChain(List<X509Certificate> certs) {
        List<String> errors = new ArrayList<>();

        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = certs.get(i);

            // Check validity period
            try {
                cert.checkValidity();
            } catch (Exception e) {
                errors.add("Certificate " + i + " validity error: " + e.getMessage());
            }

            // Verify signature (except for last cert which is self-signed or signed by
            // external root)
            if (i < certs.size() - 1) {
                try {
                    cert.verify(certs.get(i + 1).getPublicKey());
                } catch (Exception e) {
                    errors.add("Certificate " + i + " signature invalid: " + e.getMessage());
                }
            }

            // Verify issuer/subject chain
            if (i < certs.size() - 1) {
                String issuer = cert.getIssuerX500Principal().getName();
                String nextSubject = certs.get(i + 1).getSubjectX500Principal().getName();
                if (!issuer.equals(nextSubject)) {
                    errors.add("Certificate " + i + " issuer mismatch");
                }
            }
        }

        // Verify last cert is from BankID CA (basic check)
        if (!certs.isEmpty()) {
            X509Certificate lastCert = certs.get(certs.size() - 1);
            String issuer = lastCert.getIssuerX500Principal().getName();
            if (!issuer.contains("BankID") && !issuer.contains("Finansiell ID-Teknik")) {
                errors.add("Root certificate not issued by BankID CA");
            }
        }

        return errors;
    }

    private String extractTagContent(String xml, String tag) {
        Pattern p = Pattern.compile("<" + tag + "[^>]*>([^<]+)</" + tag + ">");
        Matcher m = p.matcher(xml);
        return m.find() ? m.group(1) : null;
    }

    private String extractNestedTagContent(String xml, String parentTag, String childTag) {
        // Find parent tag content first
        Pattern parentPattern = Pattern.compile("<" + parentTag + "[^>]*>(.*?)</" + parentTag + ">", Pattern.DOTALL);
        Matcher parentMatcher = parentPattern.matcher(xml);
        if (parentMatcher.find()) {
            String parentContent = parentMatcher.group(1);
            // Then extract child tag content
            return extractTagContent(parentContent, childTag);
        }
        return null;
    }

    private String extractDnField(String dn, String field) {
        Pattern p = Pattern.compile("(?:^|,)\\s*" + field + "=([^,]+)", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(dn);
        if (m.find()) {
            String value = m.group(1).trim().replace("\"", "");
            if (value.startsWith("#")) {
                value = decodeHexDnValue(value);
            }
            return value;
        }
        return null;
    }

    private String decodeHexDnValue(String hex) {
        try {
            byte[] bytes = hexToBytes(hex.substring(1));
            if (bytes.length > 2) {
                return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_8);
            }
        } catch (Exception ignored) {
        }
        return hex;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    @Data
    public static class BankIdResult {
        private boolean valid;
        private String personalNumber;
        private String name;
        private String usrVisibleData;
        private String usrNonVisibleData;
        private String relyingPartyName;
        private String relyingPartyOrgNumber;
        private Instant signatureTime;
        private boolean certificateChainValid;
        private List<String> certificateChainErrors;
        private int certificateCount;
        private String error;

        public static BankIdResult invalid(String error) {
            BankIdResult r = new BankIdResult();
            r.valid = false;
            r.error = error;
            r.certificateChainErrors = new ArrayList<>();
            return r;
        }
    }
}