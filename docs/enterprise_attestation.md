# Enterprise Attestation

## Overview

The FIDO2Applet supports enterprise attestation as defined in CTAP 2.2, with the security enhancement of restricting enterprise attestation to specific relying parties.

## Features

- **RP-Filtered Enterprise Attestation**: Enterprise attestation is only available to explicitly configured relying parties
- **Multiple Attestation Certificates**: Support for separate basic and enterprise attestation certificate chains
- **Secure Configuration**: Enterprise attestation RPs can only be configured via the authenticator config command with proper PIN/UV authorization

## Configuration

### Enabling Enterprise Attestation for Specific RPs

To enable enterprise attestation for specific relying parties, use the `authenticatorConfig` command with the `enableEnterpriseAttestation` subcommand:

1. Obtain a PIN/UV auth token with the `authenticatorConfig` permission
2. Send the `authenticatorConfig` command (0x0D) with:
   - Subcommand: `0x01` (enableEnterpriseAttestation)
   - Parameters: A CBOR map containing:
     - Key `0x01`: Array of RP ID strings (max 3 RPs)

Example CBOR structure for enabling enterprise attestation for two RPs:
```
A1           # Map with 1 entry
  01         # Key: rpIds
  82         # Array with 2 items
    6B       # String of length 11
      6578616D706C652E636F6D  # "example.com"
    68       # String of length 8
      746573742E6F7267          # "test.org"
```

To disable enterprise attestation (clear all RPs), send the command with no parameters.

### Installing Attestation Certificates

#### Basic Attestation Certificate

Use the standard `CMD_INSTALL_CERTS` (0x46) vendor command with the format:
- AAGUID (16 bytes)
- Private key (32 bytes, optional if already loaded)
- Certificate length (2 bytes)
- CBOR array of certificates

#### Enterprise Attestation Certificate

Use the new `CMD_INSTALL_ENTERPRISE_CERTS` (0x47) vendor command with the format:
- Certificate length (2 bytes)
- CBOR array of certificates

Note: The basic attestation certificate must be installed first, as it includes the private key used for both attestation types.

## Behavior

### makeCredential with Enterprise Attestation

When a relying party requests enterprise attestation (using the `enterpriseAttestation` parameter):

1. The authenticator hashes the RP ID
2. Checks if the RP ID hash is in the configured enterprise attestation allowlist
3. If not in the allowlist, returns `CTAP2_ERR_UNAUTHORIZED_PERMISSION`
4. If in the allowlist and enterprise certificate is loaded, uses enterprise attestation
5. Otherwise, falls back to basic attestation

### getInfo Response

The `ep` option in the `getInfo` response is set to `true` when at least one RP ID is configured for enterprise attestation.

## Security Considerations

- Enterprise attestation RPs are stored as SHA-256 hashes of the RP IDs
- The RP allowlist is cleared on authenticator reset
- Maximum of 3 RPs can be configured for enterprise attestation
- Configuring enterprise attestation RPs requires proper PIN/UV authorization

## Use Cases

Enterprise attestation is useful in corporate environments where:
- IT administrators need to verify that credentials are generated on specific, approved authenticators
- Device attestation is required for compliance or security policies
- The organization wants to limit enterprise attestation to internal domains only

## Compatibility

This implementation follows CTAP 2.2 specifications for enterprise attestation while adding the security enhancement of RP filtering, which prevents unauthorized use of enterprise attestation by arbitrary websites.
