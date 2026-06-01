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
    {:req_dpop, "~> 0.5"}
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

By default, ReqDPoP retries once when a response is a DPoP nonce challenge:

- status `400` or `401`
- a `DPoP-Nonce` response header
- a `WWW-Authenticate` header containing `DPoP` and `use_dpop_nonce`

The retry proof includes the server nonce. Configure this behavior with
`:retry_on_nonce` and `:max_nonce_retries`.

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
- URL query strings and fragments are excluded from `htu`.
- Supported signing algorithms are `:es256` and `:rs256`.

## Development

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
