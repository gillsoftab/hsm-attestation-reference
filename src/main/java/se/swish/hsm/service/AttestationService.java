package se.swish.hsm.service;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import se.swish.hsm.model.*;
import se.swish.hsm.model.VerificationResponse.CertificateType;
import se.swish.hsm.verification.AzureHsmVerifier;
import se.swish.hsm.verification.GoogleCloudHsmVerifier;
import se.swish.hsm.verification.SecurosysVerifier;
import se.swish.hsm.verification.YubicoVerifier;

import java.io.StringReader;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.*;

@Service
public class AttestationService {

    private final BankIdService bankIdService;
    private final SecurosysVerifier securosysVerifier;
    private final YubicoVerifier yubicoVerifier;
    private final AzureHsmVerifier azureVerifier;
    private final GoogleCloudHsmVerifier googleVerifier;

    public AttestationService(BankIdService bankIdService,
            SecurosysVerifier securosysVerifier,
            YubicoVerifier yubicoVerifier,
            AzureHsmVerifier azureVerifier,
            GoogleCloudHsmVerifier googleVerifier) {
        this.bankIdService = bankIdService;
        this.securosysVerifier = securosysVerifier;
        this.yubicoVerifier = yubicoVerifier;
        this.azureVerifier = azureVerifier;
        this.googleVerifier = googleVerifier;
    }

    public VerificationResponse verify(CertificateRequest request) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        CertificateType certType = request.requiresHsmAttestation()
                ? CertificateType.SIGNING
                : CertificateType.TRANSPORT;

        // Parse CSR
        PublicKey csrPublicKey;
        String keyAlgorithm;
        try {
            PKCS10CertificationRequest csr = parseCsr(request.getCsr());
            csrPublicKey = extractPublicKey(csr);
            keyAlgorithm = csrPublicKey.getAlgorithm();
        } catch (Exception e) {
            errors.add("Invalid CSR: " + e.getMessage());
            return buildErrorResponse(errors, certType);
        }

        String csrFingerprint = fingerprint(csrPublicKey);

        // Verify BankID
        BankIdService.BankIdResult bankIdResult = bankIdService.verify(request.getBankIdSignatureResponse(),
                request.getBankIdOcspResponse());
        if (!bankIdResult.isValid()) {
            errors.add("BankID verification failed: " + bankIdResult.getError());
        }

        boolean authorizedSignatory = verifySignatoryRights(
                bankIdResult.getPersonalNumber(),
                request.getOrganisationNumber());
        if (!authorizedSignatory) {
            warnings.add("Could not verify signatory rights - manual review required");
        }

        // HSM attestation
        String attestedFingerprint = null;
        String hsmVendor = null;
        String hsmModel = null;
        String hsmSerial = null;
        String keyOrigin = null;
        boolean keyExportable = true;
        boolean publicKeyMatch = false;
        boolean attestationChainValid = false;

        if (certType == CertificateType.SIGNING) {
            HsmVendor vendor = detectVendor(request.getHsmVendor());
            if (vendor == null) {
                errors.add("hsmVendor is required for signing certificates");
            } else {
                hsmVendor = vendor.getVendorName();

                switch (vendor) {
                    case SECUROSYS -> {
                        var result = verifySecurosys(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getHsmSerialNumber();
                        hsmModel = "Primus HSM";
                        if (result.getKeySize() != null) {
                            hsmModel += " (" + result.getAlgorithm() + " " + result.getKeySize() + ")";
                        }
                        keyOrigin = "generated"; // Securosys: never_extractable=true means generated
                        keyExportable = result.isExtractable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case YUBICO -> {
                        var result = verifyYubico(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getDeviceSerial();
                        hsmModel = "YubiHSM 2";
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isKeyExportable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case AZURE -> {
                        var result = verifyAzure(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getHsmPool();
                        hsmModel = "Azure Managed HSM";
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isExportable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    case GOOGLE -> {
                        var result = verifyGoogle(request, csrPublicKey);
                        publicKeyMatch = result.isPublicKeyMatch();
                        attestationChainValid = result.isChainValid();
                        hsmSerial = result.getKeyId();
                        hsmModel = "Google Cloud HSM";
                        if (result.getKeySize() > 0) {
                            hsmModel += " (" + result.getKeyType() + " " + result.getKeySize() + ")";
                        }
                        keyOrigin = result.getKeyOrigin();
                        keyExportable = result.isExtractable();
                        if (!result.isValid()) {
                            errors.addAll(result.getErrors());
                        }
                        if (result.isPublicKeyMatch()) {
                            attestedFingerprint = csrFingerprint;
                        }
                    }
                    default -> errors.add("Vendor " + vendor + " not yet implemented");
                }
            }
        }

        boolean valid = errors.isEmpty() && bankIdResult.isValid();
        if (certType == CertificateType.SIGNING) {
            valid = valid && publicKeyMatch && attestationChainValid;
        }

        return VerificationResponse.builder()
                .valid(valid)
                .certificateType(certType)
                .csrPublicKeyFingerprint(csrFingerprint)
                .csrPublicKeyAlgorithm(keyAlgorithm)
                .attestedPublicKeyFingerprint(attestedFingerprint)
                .hsmVendor(hsmVendor)
                .hsmModel(hsmModel)
                .hsmSerialNumber(hsmSerial)
                .publicKeyMatch(publicKeyMatch)
                .attestationChainValid(attestationChainValid)
                .keyOrigin(keyOrigin)
                .keyExportable(keyExportable)
                .bankIdSignatureValid(bankIdResult.isValid())
                .bankIdCertificateChainValid(bankIdResult.isCertificateChainValid())
                .bankIdCertificateCount(bankIdResult.getCertificateCount())
                .bankIdPersonalNumber(maskPersonalNumber(bankIdResult.getPersonalNumber()))
                .bankIdName(bankIdResult.getName())
                .bankIdUsrVisibleData(bankIdResult.getUsrVisibleData())
                .bankIdUsrNonVisibleData(bankIdResult.getUsrNonVisibleData())
                .bankIdRelyingPartyName(bankIdResult.getRelyingPartyName())
                .bankIdRelyingPartyOrgNumber(bankIdResult.getRelyingPartyOrgNumber())
                .bankIdSignatureTime(bankIdResult.getSignatureTime())
                .organisationNumber(request.getOrganisationNumber())
                .swishNumber(request.getSwishNumber())
                .authorizedSignatory(authorizedSignatory)
                .errors(errors)
                .warnings(warnings)
                .build();
    }

    private SecurosysVerifier.SecurosysAttestationResult verifySecurosys(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationData (XML) is required for Securosys");
            return result;
        }
        if (request.getAttestationSignature() == null) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationSignature is required for Securosys");
            return result;
        }
        if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
            var result = new SecurosysVerifier.SecurosysAttestationResult();
            result.addError("attestationCertChain is required for Securosys");
            return result;
        }

        return securosysVerifier.verifySecurosysAttestation(
                request.getAttestationData(),
                request.getAttestationSignature(),
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private YubicoVerifier.YubicoAttestationResult verifyYubico(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationCertChain() == null || request.getAttestationCertChain().isEmpty()) {
            var result = new YubicoVerifier.YubicoAttestationResult();
            result.addError("attestationCertChain is required for Yubico");
            return result;
        }

        return yubicoVerifier.verifyYubicoAttestation(
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private AzureHsmVerifier.AzureAttestationResult verifyAzure(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
            var result = new AzureHsmVerifier.AzureAttestationResult();
            result.addError("attestationData (JSON from az keyvault key get-attestation) is required for Azure");
            return result;
        }

        return azureVerifier.verifyAzureAttestation(
                request.getAttestationData(),
                csrPublicKey);
    }

    private GoogleCloudHsmVerifier.GoogleAttestationResult verifyGoogle(
            CertificateRequest request, PublicKey csrPublicKey) {

        if (request.getAttestationData() == null || request.getAttestationData().isBlank()) {
            var result = new GoogleCloudHsmVerifier.GoogleAttestationResult();
            result.addError(
                    "attestationData (base64 of decompressed attestation.dat) is required for Google Cloud HSM");
            return result;
        }

        return googleVerifier.verifyGoogleAttestation(
                request.getAttestationData(),
                request.getAttestationCertChain(),
                csrPublicKey);
    }

    private HsmVendor detectVendor(String specified) {
        if (specified == null || specified.isBlank())
            return null;
        try {
            return HsmVendor.valueOf(specified.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private boolean verifySignatoryRights(String personalNumber, String organisationNumber) {
        // PLACEHOLDER: Check personalNumber, organisationNumber against assigned Swish
        // agreement (number) or similar.
        return true;
    }

    private String maskPersonalNumber(String pnr) {
        if (pnr == null || pnr.length() < 12)
            return pnr;
        return pnr.substring(0, 8) + "****";
    }

    private PKCS10CertificationRequest parseCsr(String csrInput) throws Exception {
        String pem = csrInput.trim();
        if (!pem.contains("BEGIN")) {
            pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + csrInput + "\n-----END CERTIFICATE REQUEST-----";
        }
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return (PKCS10CertificationRequest) parser.readObject();
        }
    }

    private PublicKey extractPublicKey(PKCS10CertificationRequest csr) throws Exception {
        var pkInfo = csr.getSubjectPublicKeyInfo();
        var keySpec = new java.security.spec.X509EncodedKeySpec(pkInfo.getEncoded());
        String algorithm = pkInfo.getAlgorithm().getAlgorithm().getId();
        String keyAlg = algorithm.startsWith("1.2.840.10045") ? "EC" : "RSA";
        return java.security.KeyFactory.getInstance(keyAlg).generatePublic(keySpec);
    }

    private String fingerprint(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(key.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x:", b & 0xff));
            }
            return sb.substring(0, sb.length() - 1);
        } catch (Exception e) {
            return "error";
        }
    }

    private VerificationResponse buildErrorResponse(List<String> errors, CertificateType type) {
        return VerificationResponse.builder()
                .valid(false)
                .certificateType(type)
                .errors(errors)
                .warnings(Collections.emptyList())
                .build();
    }
}