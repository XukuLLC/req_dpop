# Changelog

## v0.5.1

- Correct the README installation snippet now that the package is published on
  Hex.

## v0.5.0

- Initial Req plugin for RFC 9449 DPoP proof generation.
- Adds DPoP proof and optional `Authorization: DPoP ...` headers.
- Computes `ath` for access-token mode.
- Supports proof-only token endpoint requests.
- Retries DPoP nonce challenges with a nonce-bound proof.
- Supports ES256 and RS256 signing keys.
