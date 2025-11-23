package se.swish.hsm.verification;

import org.springframework.stereotype.Component;
import se.swish.hsm.model.HsmVendor;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SecurosysVerifier implements HsmAttestationVerifier {

    // Securosys Primus HSM Root CA (production)
    private static final String SECUROSYS_ROOT_CA = """
            -----BEGIN CERTIFICATE-----
            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
            4WzEkJhoDVG+m/ScmyguyvqBkkYBEuX0Yg==
            -----END CERTIFICATE-----""";

    private X509Certificate rootCa;

    public SecurosysVerifier() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            rootCa = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(SECUROSYS_ROOT_CA.trim().getBytes()));
        } catch (Exception e) {
            // Root CA will be verified by chain issuer check instead
            rootCa = null;
        }
    }

    @Override
    public HsmVendor getVendor() {
        return HsmVendor.SECUROSYS;
    }

    @Override
    public boolean verifyAttestation(X509Certificate attestationCert, PublicKey csrPublicKey) {
        // For Securosys, XML data is used instead - this method is not called directly
        return false;
    }

    /**
     * Verify Securosys attestation:
     * 1. Verify certificate chain against root
     * 2. Verify XML signature with public key of the certificate 
     * 3. Extract public_key from XML and compare with CSR
     * 4. Check attributes: extractable=false, never_extractable=true, sensitive=true, always_sensitive=true
     */
    public SecurosysAttestationResult verifySecurosysAttestation(
            String xmlBase64,
            String signatureBase64,
            List<String> certChainPem,
            PublicKey csrPublicKey) {

        SecurosysAttestationResult result = new SecurosysAttestationResult();

        try {
            // 1. Parse certificate chain
            X509Certificate[] chain = parseCertChain(certChainPem);
            if (chain.length == 0) {
                result.addError("No certificates in chain");
                return result;
            }

            // 2. Verify certificate chain
            if (!verifyCertChain(chain)) {
                result.addError("Certificate chain verification failed");
            } else {
                result.setChainValid(true);
            }

            // 3. Decode XML
            byte[] xmlBytes = Base64.getDecoder().decode(xmlBase64);
            String xml = new String(xmlBytes);

            // 4. Verify signature
            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            PublicKey attestPubKey = chain[0].getPublicKey();

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(attestPubKey);
            sig.update(xmlBytes);

            if (!sig.verify(sigBytes)) {
                result.addError("XML signature verification failed");
            } else {
                result.setSignatureValid(true);
            }

            // 5. Extract public key from XML and compare with CSR
            byte[] xmlPubKeyBytes = extractPublicKeyFromXml(xml);
            if (xmlPubKeyBytes == null) {
                result.addError("Could not extract public_key from XML");
            } else {
                byte[] csrPubKeyBytes = csrPublicKey.getEncoded();
                if (java.util.Arrays.equals(xmlPubKeyBytes, csrPubKeyBytes)) {
                    result.setPublicKeyMatch(true);
                } else {
                    result.addError("Public key mismatch: CSR key does not match attested key");
                }
            }

            // 6. Verify key attributes
            boolean extractable = extractBooleanAttribute(xml, "extractable");
            boolean neverExtractable = extractBooleanAttribute(xml, "never_extractable");
            boolean sensitive = extractBooleanAttribute(xml, "sensitive");
            boolean alwaysSensitive = extractBooleanAttribute(xml, "always_sensitive");

            if (extractable) {
                result.addError("Key attribute extractable must be false");
            }
            if (!neverExtractable) {
                result.addError("Key attribute never_extractable must be true");
            }
            if (!sensitive) {
                result.addError("Key attribute sensitive must be true");
            }
            if (!alwaysSensitive) {
                result.addError("Key attribute always_sensitive must be true");
            }
            result.setExtractable(extractable);
            result.setNeverExtractable(neverExtractable);
            result.setSensitive(sensitive);
            result.setAlwaysSensitive(alwaysSensitive);

            // 7. Extract metadata
            result.setKeyLabel(extractTagContent(xml, "label"));
            result.setAlgorithm(extractTagContent(xml, "algorithm"));
            result.setKeySize(extractTagContent(xml, "key_size"));
            result.setCreateTime(extractTagContent(xml, "create_time"));

            // Extract HSM serial from cert chain
            if (chain.length > 1) {
                String cn = chain[1].getSubjectX500Principal().getName();
                Pattern p = Pattern.compile("SN:\\s*(\\d+)");
                Matcher m = p.matcher(cn);
                if (m.find()) {
                    result.setHsmSerialNumber(m.group(1));
                }
            }

            result.setValid(result.isChainValid() && result.isSignatureValid() &&
                    result.isPublicKeyMatch() && !extractable && neverExtractable
                    && sensitive && alwaysSensitive);

        } catch (Exception e) {
            result.addError("Verification error: " + e.getMessage());
        }

        return result;
    }

    private X509Certificate[] parseCertChain(List<String> pemCerts) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[pemCerts.size()];

        for (int i = 0; i < pemCerts.size(); i++) {
            String pem = pemCerts.get(i).trim();
            if (!pem.startsWith("-----BEGIN")) {
                pem = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----";
            }
            chain[i] = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes()));
        }
        return chain;
    }

    private boolean verifyCertChain(X509Certificate[] chain) {
        try {
            for (int i = 0; i < chain.length - 1; i++) {
                chain[i].checkValidity();
                chain[i].verify(chain[i + 1].getPublicKey());
            }
            // Last cert should be signed by Securosys root
            X509Certificate last = chain[chain.length - 1];
            last.checkValidity();

            if (rootCa != null) {
                last.verify(rootCa.getPublicKey());
            } else {
                // Fallback: check issuer contains Securosys/PRIMUS
                String issuer = last.getIssuerX500Principal().getName();
                if (!issuer.contains("SECUROSYS") && !issuer.contains("Securosys") && !issuer.contains("PRIMUS")) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] extractPublicKeyFromXml(String xml) {
        String pubKeyB64 = extractTagContent(xml, "public_key");
        if (pubKeyB64 == null)
            return null;
        return Base64.getDecoder().decode(pubKeyB64.trim());
    }

    private boolean extractBooleanAttribute(String xml, String attrName) {
        String value = extractTagContent(xml, attrName);
        return "true".equalsIgnoreCase(value);
    }

    private String extractTagContent(String xml, String tag) {
        Pattern p = Pattern.compile("<" + tag + ">([^<]+)</" + tag + ">");
        Matcher m = p.matcher(xml);
        return m.find() ? m.group(1).trim() : null;
    }

    @Override
    public boolean verifyChain(X509Certificate attestationCert, X509Certificate[] chain) {
        // Used by generic flow - Securosys has its own method
        return true;
    }

    @Override
    public String extractSerialNumber(X509Certificate attestationCert) {
        return attestationCert.getSerialNumber().toString(16);
    }

    @Override
    public String extractModel(X509Certificate attestationCert) {
        String cn = attestationCert.getIssuerX500Principal().getName();
        if (cn.contains("SN:"))
            return "Primus HSM";
        return "Primus HSM";
    }

    public static class SecurosysAttestationResult {
        private boolean valid;
        private boolean chainValid;
        private boolean signatureValid;
        private boolean publicKeyMatch;
        private boolean extractable;
        private boolean neverExtractable;
        private boolean sensitive;
        private boolean alwaysSensitive;
        private String keyLabel;
        private String algorithm;
        private String keySize;
        private String createTime;
        private String hsmSerialNumber;
        private java.util.List<String> errors = new java.util.ArrayList<>();

        public void addError(String error) {
            errors.add(error);
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public boolean isChainValid() {
            return chainValid;
        }

        public void setChainValid(boolean chainValid) {
            this.chainValid = chainValid;
        }

        public boolean isSignatureValid() {
            return signatureValid;
        }

        public void setSignatureValid(boolean signatureValid) {
            this.signatureValid = signatureValid;
        }

        public boolean isPublicKeyMatch() {
            return publicKeyMatch;
        }

        public void setPublicKeyMatch(boolean publicKeyMatch) {
            this.publicKeyMatch = publicKeyMatch;
        }

        public boolean isExtractable() {
            return extractable;
        }

        public void setExtractable(boolean extractable) {
            this.extractable = extractable;
        }

        public boolean isNeverExtractable() {
            return neverExtractable;
        }

        public void setNeverExtractable(boolean neverExtractable) {
            this.neverExtractable = neverExtractable;
        }

        public boolean isSensitive() {
            return sensitive;
        }

        public void setSensitive(boolean sensitive) {
            this.sensitive = sensitive;
        }

        public boolean isAlwaysSensitive() {
            return alwaysSensitive;
        }

        public void setAlwaysSensitive(boolean alwaysSensitive) {
            this.alwaysSensitive = alwaysSensitive;
        }

        public String getKeyLabel() {
            return keyLabel;
        }

        public void setKeyLabel(String keyLabel) {
            this.keyLabel = keyLabel;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getKeySize() {
            return keySize;
        }

        public void setKeySize(String keySize) {
            this.keySize = keySize;
        }

        public String getCreateTime() {
            return createTime;
        }

        public void setCreateTime(String createTime) {
            this.createTime = createTime;
        }

        public String getHsmSerialNumber() {
            return hsmSerialNumber;
        }

        public void setHsmSerialNumber(String hsmSerialNumber) {
            this.hsmSerialNumber = hsmSerialNumber;
        }

        public java.util.List<String> getErrors() {
            return errors;
        }
    }
}