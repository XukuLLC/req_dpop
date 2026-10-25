# ReqDPoP

[![Hex.pm](https://img.shields.io/hexpm/v/req_dpop)](https://hex.pm/packages/req_dpop)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/req_dpop)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

ReqDPoP is a small [Req](https://hex.pm/packages/req) plugin for OAuth 2.0
DPoP proof generation as defined by [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).

It is not an OAuth provider, token store, or full OAuth client. It does not
fetch tokens for you. It only signs DPoP proofs for outgoing Req requests and,
when configured, attaches a DPoP-bound access token.

## Installation

```elixir
def deps do
  [
    {:req_dpop, "~> 0.6"}
  ]
end
```

## Resource Request

```elixir
key = ReqDPoP.Key.generate(:es256)

client =
  Req.new(base_url: "https://api.example.com")
  |> ReqDPoP.attach(key: key, access_token: access_token)

Req.get!(client, url: "/resource")
```

The plugin adds:

- `DPoP: <proof-jwt>`
- `Authorization: DPoP <access_token>`
- `ath` in the proof when an access token is present

`htu` and `htm` are derived from the final Req request URL and method after Req
has applied base URL and path options. Per RFC 9449, `htu` excludes the request
URL's query string and fragment.

## Token Endpoint Proof

Use proof-only mode by omitting `:access_token`:

```elixir
Req.new()
|> ReqDPoP.attach(key: key)
|> Req.post!(url: "https://auth.example.com/oauth/token", form: params)
```

## Nonce Retry

By default, ReqDPoP retries once when a response carries a single `DPoP-Nonce`
header with an RFC 9449 nonce value and is a nonce challenge in either form:

- authorization server (section 8): status `400` with a JSON body of
  `{"error": "use_dpop_nonce"}`, on proof-only requests
- resource server (section 9): status `401` with a `WWW-Authenticate` header
  whose `DPoP` challenge carries `error="use_dpop_nonce"`

The retry proof includes the server nonce. Nonces and the retry budget are
tracked per origin. Configure this behavior with `:retry_on_nonce` and
`:max_nonce_retries`.

A compressed challenge body is decoded only when the request was made with
Req's `compressed: true`, the same opt-in Req applies to every response body.

## Redirects and Retries

Each hop of a request gets its own proof for the hop's method and URL with a
fresh `jti`, including hops made by Req's `retry` and `redirect` steps.

On an untrusted cross-origin redirect, Req removes the `Authorization` header.
ReqDPoP then removes the `DPoP` header as well, in proof-only mode too, so the
redirect target receives neither the token nor a proof. Set Req's
`redirect_trusted: true` to send both to the new origin.

## Key Persistence

Generated keys are process-local values. Production clients should persist the
DPoP key if they need stable sender binding across restarts:

```elixir
key = ReqDPoP.Key.generate(:es256)
jwk = ReqDPoP.Key.export(key)
key = ReqDPoP.Key.load!(jwk)
```

## Security Notes

- Do not log access tokens or private JWKs.
- Do not store tokens globally.
- `ath` is SHA-256 over the ASCII access token, encoded as unpadded base64url.
- `htu` is the wire form of the target URI: lowercase scheme and host, `/` for
  an empty path, and no userinfo, query, or fragment.
- The proof `jwk` header carries only the RFC 7638 thumbprint members of the
  key. Other members of a loaded JWK map, such as `kid`, stay out of the proof.
- Keys are validated on load: a complete private P-256 EC key, or a private
  RSA key of at least 2048 bits. `inspect/1` of a key shows the algorithm only.
- A plain-string `:access_token` is kept out of `inspect/1` output for the
  request. Passing a zero-arity function works as well.
- Req's `:auth` option and `:access_token` both set `Authorization`; setting
  both raises.
- Supported signing keys are P-256 EC (ES256) and RSA (RS256).

## Development

The test suite includes server-side interop checks against Attesto's DPoP
verifier as a test-only dependency; Attesto is not required at runtime.

```sh
mix format --check-formatted
mix compile --warnings-as-errors
mix credo --strict
mix test
mix docs
mix hex.build
```

## License

MIT. See [LICENSE](LICENSE).
