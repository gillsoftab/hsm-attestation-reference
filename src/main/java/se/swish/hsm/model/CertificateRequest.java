package se.swish.hsm.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import java.util.List;

@Data
public class CertificateRequest {

    @NotBlank(message = "CSR is required")
    private String csr;

    @NotBlank(message = "BankID signature is required")
    private String bankIdSignatureResponse;

    private String bankIdOcspResponse;

    @NotBlank(message = "Organisation number is required")
    @Pattern(regexp = "^\\d{10}(\\d{2})?$", message = "Organisation number must be 10 or 12 digits")
    private String organisationNumber;

    @NotBlank(message = "Swish number is required")
    @Pattern(regexp = "^(123|987)\\d{7}$", message = "Swish number must start with 123 or 987 followed by 7 digits")
    private String swishNumber;

    // HSM Vendor - required for signing certificates
    private String hsmVendor; // YUBICO, SECUROSYS, AZURE, GOOGLE

    // === HSM Attestation Data (vendor-specific) ===

    // Yubico: attestation certificate (contains public key)
    // Securosys: XML attestation file (base64)
    // Cloud HSMs: attestation document
    private String attestationData;

    // Securosys only: signature file (.sig) base64
    private String attestationSignature;

    // Certificate chain (excluding root which is on server)
    // Yubico: [attestation_cert, device_cert, intermediate_cert]
    // Securosys: [attestation_cert, device_cert]
    private List<String> attestationCertChain;

    public boolean requiresHsmAttestation() {
        return (attestationData != null && !attestationData.isBlank()) || (attestationCertChain != null && !attestationCertChain.isEmpty());
    }
}