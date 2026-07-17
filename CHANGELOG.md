# Changelog

## v0.5.3

- Raise the JOSE dependency floor to 1.11.12. This keeps the earlier security,
  package-metadata, and Erlang/OTP 28 EC key fixes while also correctly
  encoding Elixir `nil` as JSON `null` with Erlang/OTP's built-in JSON module.

## v0.5.2

- Raise the Req dependency floor to 0.6.1, the first release patched for
  EEF-CVE-2026-49755 decompression-bomb denial of service.

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
