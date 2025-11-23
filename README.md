# HSM Attestation Reference Implementation for Swish

Reference implementation for verification of HSM attestation in Swish certificate requests according to DORA/Cybersecurity Act.

## Flow

```
┌─────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Client    │──────│  Attestation API │──────│  Getswish   │
│             │      │                  │      │     CA      │
│ CSR         │      │ 1. Parse CSR     │      │             │
│ BankID-sig  │      │ 2. Verify BankID │      │ Issue       │
│ OrgNo       │      │ 3. Verify HSM*   │      │ certificate │
│ SwishNo     │      │                  │      │             │
│ Attestation*│      │                  │      │             │
└─────────────┘      └──────────────────┘      └─────────────┘
                     * For signing certificates only
```

## Certificate types

| Type | Usage | HSM attestation |
|-----|------------|-----------------|
| TRANSPORT | mTLS to Swish API | No |
| SIGNING | Sign payouts | Yes (DORA requirement) |

## API

### POST /api/v1/attestation/verify

**Request:**
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIE...",
  "bankIdSignatureResponse": "PD94bWwgdmVyc2lvbj0iMS4wI...",
  "organisationNumber": "5569741234",
  "swishNumber": "1234567890",
  "hsmVendor": "SECUROSYS",              // Optional - autodetect
  "attestationData": "PD94bWwgdmVyc2lvbj0iMS4wI...",    // Optional if not SIGNING (Not YubiHSM 2)
  "attestationSignature": "eywPlJWUEiLDnaq+NEAs4zB3RbpKJlAd...",    // Optional if not SIGNING with SECUROSYS
  "attestationCertChain": ["-----BEGIN CERTIFICATE-----\n...", "-----BEGIN CERTIFICATE-----\n..."] // If not empty → SIGNING
}
```

**Response for signing certificate:**
```json
{
  "valid": true,
  "certificateType": "SIGNING",
  "csrPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "csrPublicKeyAlgorithm": "RSA",
  "attestedPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "hsmVendor": "Securosys",
  "hsmModel": "Primus HSM",
  "hsmSerialNumber": "18000000",
  "publicKeyMatch": true,
  "attestationChainValid": true,
  "keyOrigin": "generated",
  "keyExportable": false,
  "bankIdSignatureValid": true,
  "bankIdCertificateChainValid": true,
  "bankIdCertificateCount": 3,
  "bankIdPersonalNumber": "19880807****",
  "bankIdName": "Test Testsson",
  "bankIdUsrVisibleData": "Bolagsnamn AB (556954-1234) ger härmed Teknisk leverantör AB (556964-1234) fullmakt att hämta fyra (4) Swish-certifikat för Swish-nummer 1234567890 kopplat till TL-nummer 9876543210.",
  "bankIdUsrNonVisibleData": "0b7ee6f76c72db770ed5c7fb2d01f9d6a5e9e3160fe9e4f37c678167d055af1e",
  "bankIdRelyingPartyName": "Teknisk leverantör AB",
  "bankIdRelyingPartyOrgNumber": "5569641234",
  "organisationNumber": "5569541234",
  "swishNumber": "1234567890",
  "authorizedSignatory": true,
  "errors": [],
  "warnings": []
}
```

**Response for transport certificate:**
```json
{
  "valid": true,
  "certificateType": "TRANSPORT",
  "csrPublicKeyFingerprint": "c2:e7:bc:ce:c8:ae:e1:ed:22:df:6d:69:6d:ba:45:7f:59:55:4b:28:9b:65:08:92:f9:9b:3e:5c:c7:0d:e0:6f",
  "csrPublicKeyAlgorithm": "RSA",
  "attestedPublicKeyFingerprint": null,
  "hsmVendor": null,
  "hsmModel": null,
  "hsmSerialNumber": null,
  "publicKeyMatch": false,
  "attestationChainValid": false,
  "keyOrigin": null,
  "keyExportable": true,
  "bankIdSignatureValid": true,
  "bankIdCertificateChainValid": true,
  "bankIdCertificateCount": 3,
  "bankIdPersonalNumber": "19880807****",
  "bankIdName": "Test Testsson",
  "bankIdUsrVisibleData": "Bolagsnamn AB (556954-1234) ger härmed Teknisk leverantör AB (556964-1234) fullmakt att hämta fyra (4) Swish-certifikat för Swish-nummer 1234567890 kopplat till TL-nummer 9876543210.",
  "bankIdUsrNonVisibleData": "0b7ee6f76c72db770ed5c7fb2d01f9d6a5e9e3160fe9e4f37c678167d055af1e",
  "bankIdRelyingPartyName": "Teknisk leverantör AB",
  "bankIdRelyingPartyOrgNumber": "5569641234",
  "organisationNumber": "5569541234",
  "swishNumber": "1234567890",
  "authorizedSignatory": true,
  "errors": [],
  "warnings": []
}
```

## Verification logic

1. **CSR**: Extract public key
2. **BankID**: Verify signature → extract personal identification number
3. **Certificate Manager**: Verify that this personal identification number are allowed to issue certificates for the organization number or Swish number.
4. **HSM attestation** (SIGNING only):
   - Verify that public key in CSR = attestation key
   - Verify attestation certificate chain against HSM manufacturer's CA
5. **Issue certificate**: `Swish issues transport certificate or signing certificate`

## Supported HSM vendors

| Vendor | Status | Request format |
|--------|--------|----------------|
| Securosys Primus | ✅ | `attestationData` (XML), `attestationSignature`, `attestationCertChain` |
| Yubico YubiHSM 2 | ✅ | `attestationCertChain` |
| Azure Managed HSM | ✅ | `attestationData` (JSON from `az keyvault key get-attestation`) |
| Google Cloud HSM | ✅ | `attestationData`, `attestationCertChain` |
| AWS CloudHSM | ❌ | Lacks per-key attestation |


## Azure Managed HSM

The client retrieves:
```bash
az keyvault key get-attestation --hsm-name contoso --name mykey --file attestation.json
```

Request:
```json
{
  "hsmVendor": "AZURE",
  "attestationData": "<content from attestation.json>",
  ...
}
```

## Google Cloud HSM

The client must:
```bash
# 1. Download attestation and certificate chain
gcloud kms keys versions describe 1 \
  --key mykey --keyring myring --location global \
  --attestation-file attestation.dat.gz

gcloud kms keys versions get-certificate-chain 1 \
  --key mykey --keyring myring --location global \
  --output-file certs.pem

# 2. Decompress attestation
gunzip attestation.dat.gz

# 3. Base64 encode for API calls
base64 attestation.dat > attestation.b64
```

Request:
```json
{
  "hsmVendor": "GOOGLE",
  "attestationData": "<content from attestation.b64>",
  "attestationCertChain": ["<content from certs.pem>"],
  ...
}
```

## Build and run

Install extensions in VSCode or setup your dev environment for Java and Spring Boot:

```bash
vscjava.vscode-java-pack
vmware.vscode-boot-dev-pack
```

```bash
mvn clean package
java -jar target/hsm-attestation-reference-1.0.0.jar
```

**Swagger UI:**
http://localhost:8080/swagger-ui.html
http://localhost:8080/swagger-ui/index.html

## Production

Requires:
- HSM manufacturer root CAs (included for Yubico/Securosys)

## License

MIT - Gillsoft AB
