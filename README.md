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
Use bankIdOcspResponse to verify signing time and add it to `bankIdSignatureTime` in the output.
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIE...",
  "bankIdSignatureResponse": "PD94bWwgdmVyc2lvbj0iMS4wI...",
  "bankIdOcspResponse": "MIIHmgoBAKCCB5MwggePBgkrBgEFBQcwAQEEggeAMIIHfDCCATGhgY0wgYoxCzAJBgNVBAYTAlNFMTAwLgYDVQQKDCdTa2FuZGluYXZpc2thIEVuc2tpbGRhIEJhbmtlbiBBQiAocHVibCkxEzARBgNVBAUTCjUwMjAzMjkwODExNDAyBgNVBAMMK1NFQiBDdXN0b21lciBDQTMgdjEgZm9yIEJhbmtJRCBPQ1NQIFNpZ25pbmcYDzIwMjUxMTIzMDcxODU3WjBYMFYwQTAJBgUrDgMCGgUABBQXO089wTW7MboTMxka2Kfgw4dAQgQUhywBjeCqvk2X7eMmfYDu8ljDljkCCEDGQ45xQqn4gAAYDzIwMjUxMTIzMDcxODU3WqE0MDIwMAYJKwYBBQUHMAECAQH/BCBj49LfyUHVPrjpg5npLgQryG+Qt4+YgPF6E/iZNDlbHzANBgkqhkiG9w0BAQsFAAOCAQEAGwvNfCYEGHhIL93jxYr+9hAQZFVQB7jHKnxGlIqKTEA5vrVo7sOb4nlokQo8BU7ydSATdvC1iyJXRbgTPjF6jlZkXKiqo6wi8rB09VT/FQ6S4fw5hSJq7qAtQHq6atPipGmBLYyAAJsaUX5YowRV72X2C/cJue8fi1PcAbEXyeDjZDvP55iW1/dUcGw3MsB1w76O+TanZBGSu2D9oTTx6RzOJGEJSR7BfTj7oVgBn3BOqbYfucyoLsD8wK66L+bBMKtc9iSX7aaHxRZw5ggXaFYchJO1hxLmdvjoopIKM7eMPuy/1Y5AC0PUeKPs9hxPTgJ3zajS9lvC9eOsm6a7AKCCBS8wggUrMIIFJzCCAw+gAwIBAgIIBdUu7KHA03AwDQYJKoZIhvcNAQELBQAwfTELMAkGA1UEBhMCU0UxMDAuBgNVBAoMJ1NrYW5kaW5hdmlza2EgRW5za2lsZGEgQmFua2VuIEFCIChwdWJsKTETMBEGA1UEBRMKNTAyMDMyOTA4MTEnMCUGA1UEAwweU0VCIEN1c3RvbWVyIENBMyB2MSBmb3IgQmFua0lEMB4XDTI1MDkyOTEyNDU1NVoXDTI2MDMyODEyNDU1NFowgYoxCzAJBgNVBAYTAlNFMTAwLgYDVQQKDCdTa2FuZGluYXZpc2thIEVuc2tpbGRhIEJhbmtlbiBBQiAocHVibCkxEzARBgNVBAUTCjUwMjAzMjkwODExNDAyBgNVBAMMK1NFQiBDdXN0b21lciBDQTMgdjEgZm9yIEJhbmtJRCBPQ1NQIFNpZ25pbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgTPqC0rx4GDqnz1IkKW/ryEL5UaCeHdZqzW0v66p5yVTMSpIgUD5rM6IjqJK4HE9uYkI0AyaHmkTwmxWTkutL1UEv6zMeRig/aCkq3rZaBV4beefUIztHp986NYfMsflK1j46fibRUals5nwKW0+Obkf9CrkCaWjLMIh5M6f29D/mIInRgQC6JetRlTmSCZKfAu0VzzLYZOZQubm3WUyDUXsOtTWdFJScbtEp+3iy2V9hgBy2+HPK7Fb2gfVHAfUFJ97mN8y6uoaFfehBRnaIHdF/jboCkGPrGP2pKTy89yh57XEabmq2fGRdqAzrm29lhczFj754ybL+9l7+amVNAgMBAAGjgZwwgZkwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSHLAGN4Kq+TZft4yZ9gO7yWMOWOTATBgNVHSAEDDAKMAgGBiqFcE4BATAPBgkrBgEFBQcwAQUEAgUAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBSgRoTefP4q5S15CS8sIYntUZT5nTAOBgNVHQ8BAf8EBAMCBkAwDQYJKoZIhvcNAQELBQADggIBAA2oeSsA8tlPdK8DSohJUztgbfgiEmngZ8Uyion6BqPJ6oSNzPaDdelKdHlNDaSqHoxugzKBMHW2O2yT88PWCC9ljT1goseV/j5/g0CJtWp3a8Lngm9rcAURzVObaEzvTyPLXA0ozQeJrOysVjQKnPqaxxMyS7Ef/1ok/cJiEHYa4Flu0MuFmrLvrYKBrumY/UN+COe4qow5Qwcrki/T6cSEDi7Yz7Dc6M7OjA1ZpFOBXpwcfLBrSVp3Mbv2CwBJQhzVNYgS+PZ630qhUun6Il//msIFWFNeACecxpelBz1MDkjChq0mXliUVjLy+6tNHieB4g23FiAGqig1TgDH8+9LxMAWRDhgNLYXSttz5ucwFrCJqhIzSTaRlzy3VYSTENggVh3aktkO/8wu6gUjZpGS/EpeT+hwQxZ+Ai6AOK8RcQcHYajUV3QGo686RK2I3+wB6VuhOq0gy0pIqioynyTXg/4bAIH000ixNcL8SuLZ53HlUGHe3KMcS/XMgBAtWbpjcpJ72Fu0m/jmJtC1Sla46iO0ccTrKGPk7MNMZCSrQlp/wQy4q0xAMCP9PlgQCJv8a3LJDJspX1sdlE82OMqoPoXanZjGeuykTbvqcJLIQ2ub8L2TiOMfFWELzR/y6x8/PiWAyQMOlz3hUd8qSrpUG71ySDFWsjZknDaTpwBg",
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
  "bankIdSignatureTime": "2025-11-23T07:18:57Z",
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
  "bankIdSignatureTime": "2025-11-23T07:18:57Z",
  "organisationNumber": "5569541234",
  "swishNumber": "1234567890",
  "authorizedSignatory": true,
  "errors": [],
  "warnings": []
}
```

## Verification logic

1. **CSR**: Extract public key
2. **BankID**: Verify signature → extract personal identification number, signature time and verify that ocsp serial number matches the serial number in the user certificate in bankIdSignatureResponse.
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

### The client retrieves
az keyvault key get-attestation --hsm-name contoso --name mykey --file attestation.json
```

### Sending to server
curl -X POST .../verify -d '{
  "hsmVendor": "AZURE",
  "attestationData": "<content from attestation.json>",
  ...
}'

### Google Cloud HSM

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
