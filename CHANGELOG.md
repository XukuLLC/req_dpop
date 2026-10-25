# Changelog

## v0.6.0

Security:

- With Req 0.7 and later, an untrusted cross-origin redirect re-attached
  `Authorization: DPoP <token>` and a fresh proof bound to the redirect target
  after Req had removed the header. Req 0.7 re-runs every request step on a
  redirect, and the plugin read the token back from its own option. The plugin
  now signs per hop and, when Req withholds the token, sends no `DPoP` header
  either. With Req 0.6 the redirect target received the previous hop's proof
  (stale `htu`, reused `jti`) and no token; it now receives neither. Proof-only
  requests follow the same rule: no proof crosses to an untrusted origin.
- `ReqDPoP.Key.load!/1` now requires a complete private signing key: a P-256
  EC key with 32-byte `x`, `y`, and `d`, or an RSA key of at least 2048 bits
  (RFC 7518 section 3.3) with `n`, `e`, and `d`. Before, a partial or
  public-only JWK loaded and then crashed inside JOSE at signing time with the
  decoded private scalar in the stack trace arguments. Hand-built
  `%ReqDPoP.Key{}` structs are re-validated. `inspect/1` of a key shows only
  the algorithm.
- Server nonces are checked against RFC 9449 section 8 syntax (`NQCHAR`,
  at most 1024 bytes, exactly one `DPoP-Nonce` header). Before, a non-UTF-8
  nonce crashed the request with an Erlang JSON error.
- `WWW-Authenticate` parsing reads `error="use_dpop_nonce"` only from the
  `DPoP` challenge's own parameters, not from other schemes or quoted text.
- Nonce challenge bodies are decoded with the caller's own Req options. The
  body is decompressed only when the caller set `compressed: true`, which Req
  documents as opt-in because of decompression bombs, and bodies over 64 KiB
  are not inspected. The section 8 JSON form is recognized only on proof-only
  (token endpoint) requests.
- Server nonces and the nonce retry budget are tracked per origin, and a hop
  that received no proof does not answer a nonce challenge.
- `:max_nonce_retries`, `:retry_on_nonce`, `:access_token`, `:nonce`,
  `:clock`, and `:jti` are validated at `attach/2`. Before,
  `max_nonce_retries: nil` retried without bound.
- Setting Req's `:auth` option together with `:access_token` raises
  `ReqDPoP.Error` instead of silently letting one overwrite the other on
  retried hops.
- The proof `jwk` header carries only the RFC 7638 thumbprint members. Other
  members of a loaded JWK map, such as `kid` or application fields, no longer
  travel in every proof. `ReqDPoP.Key.proof_jwk/1` returns that map.
- A plain-string `:access_token` no longer appears in `inspect/1` output for
  the request, matching Req's redaction of the `Authorization` header.
- `ReqDPoP.Error` for an invalid `:key` no longer embeds the rejected value;
  the reason is `:invalid_key`.
- `mix.exs` declares `{:mint, ">= 1.10.2"}` so consumers resolve past the
  mint releases with open advisories (EEF-CVE-2026-82672, -82728, -82729,
  -91043, -92103, -94194). Development lockfile: mint 1.11.0, finch 0.24.0,
  req 0.7.5.

Fixes:

- Nonce retry recognizes the RFC 9449 section 8 authorization server
  challenge: status `400`, a JSON body of `{"error": "use_dpop_nonce"}`, and a
  `DPoP-Nonce` header, with no `WWW-Authenticate`. Before, only the section 9
  `WWW-Authenticate` form triggered a retry, so token endpoint requests never
  retried against a server that follows the RFC.
- Req's retry and redirect steps get a fresh proof (new `jti`, current `htu`
  and `htm`) instead of a replay of the previous hop's proof. With Req 0.6 the
  plugin queues its step for the re-run, including after transport errors;
  Req 0.7 re-runs every step.
- A streaming (`into:`) challenge response is cancelled before the nonce
  retry, as Req's redirect step does.
- `htu` is the wire form of the target URI: lowercase scheme and host, `/`
  for an empty path, no userinfo, query, or fragment. A relative or non-HTTP
  `htu` raises `ReqDPoP.Error`. Before, `Req.get!(client)` against a bare
  `base_url` signed `https://host` while the request line carried `/`, and
  verifiers that compare paths rejected the proof.
- An empty `:access_token` means proof-only mode: no `Authorization` header and
  no `ath` claim. Before, `ath` was computed over the empty string while the
  header was omitted.
- `:alg` must match the key type. Keys other than P-256 EC and RSA raise
  `ReqDPoP.Error` with reason `:unsupported_key` instead of a raw JOSE error.
- `attach/2` called twice on one request replaces the configuration instead
  of adding a second set of steps.
- CI pins `auth0-api-python`, fails instead of skipping when the Python
  verifier is missing, and runs the suite against Req 0.6 as well as the lock.

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
