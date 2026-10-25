defmodule ReqDPoP.Key do
  @moduledoc """
  Helpers for DPoP signing keys.

  Production clients should persist their DPoP key when they need stable
  sender binding across process restarts.

  `inspect/1` shows only the algorithm, never key material.
  """

  alias ReqDPoP.Error

  @type alg :: :es256 | :rs256
  @type t :: %__MODULE__{jwk: JOSE.JWK.t(), alg: alg()}

  @derive {Inspect, only: [:alg]}
  defstruct [:jwk, :alg]

  # RFC 7518 section 3.3: RS256 keys MUST be at least 2048 bits.
  @min_rsa_bits 2048

  @doc """
  Generates a private signing key for `:es256` or `:rs256`.
  """
  @spec generate(alg()) :: t()
  def generate(:es256), do: %__MODULE__{jwk: JOSE.JWK.generate_key({:ec, "P-256"}), alg: :es256}
  def generate(:rs256), do: %__MODULE__{jwk: JOSE.JWK.generate_key({:rsa, 2048}), alg: :rs256}

  def generate(alg) do
    raise Error,
      reason: {:unsupported_alg, alg},
      message: "unsupported DPoP signing algorithm #{inspect(alg)}"
  end

  @doc """
  Loads a `ReqDPoP.Key` from a key struct, `JOSE.JWK`, or JWK map.

  The key must be a complete private signing key: a P-256 EC key with 32-byte
  `x`, `y`, and `d`, or an RSA key of at least 2048 bits with `n`, `e`, and
  `d`. Anything else raises `ReqDPoP.Error` with reason `:invalid_key` or
  `:unsupported_key`. Error messages never include key material.
  """
  @spec load!(t() | JOSE.JWK.t() | map()) :: t()
  def load!(%__MODULE__{jwk: %JOSE.JWK{} = jwk}), do: from_jwk!(jwk)
  def load!(%JOSE.JWK{} = jwk), do: from_jwk!(jwk)

  def load!(map) when is_map(map) do
    case from_map(map) do
      {:ok, jwk} -> from_jwk!(jwk)
      :error -> raise Error, reason: :invalid_key, message: "expected a valid JWK map"
    end
  end

  def load!(_other) do
    raise Error, reason: :invalid_key, message: "expected ReqDPoP.Key, JOSE.JWK, or JWK map"
  end

  @doc """
  Returns the underlying `JOSE.JWK`.
  """
  @spec jose_jwk(t()) :: JOSE.JWK.t()
  def jose_jwk(%__MODULE__{jwk: jwk}), do: jwk

  @doc """
  Exports the private JWK as a map.
  """
  @spec export(t()) :: map()
  def export(%__MODULE__{jwk: jwk}) do
    jwk
    |> JOSE.JWK.to_map()
    |> elem(1)
  end

  @doc """
  Exports the public JWK as a map.

  The map keeps every public member of the loaded JWK, such as `kid`. The
  proof header uses `proof_jwk/1` instead.
  """
  @spec public_jwk(t()) :: map()
  def public_jwk(%__MODULE__{jwk: jwk}) do
    jwk
    |> JOSE.JWK.to_public_map()
    |> elem(1)
  end

  @doc """
  Returns the public JWK placed in the proof `jwk` header.

  Only the RFC 7638 thumbprint members are included: `crv`, `kty`, `x`, and
  `y` for EC keys; `e`, `kty`, and `n` for RSA keys. Any other member of a
  loaded JWK map stays out of the proof, so application-specific fields never
  travel with it.
  """
  @spec proof_jwk(t()) :: map()
  def proof_jwk(%__MODULE__{jwk: jwk}) do
    jwk
    |> JOSE.JWK.to_thumbprint_map()
    |> elem(1)
  end

  @doc """
  Returns the RFC 7638 SHA-256 JWK thumbprint, base64url unpadded.

  Accepts public keys as well as private ones.
  """
  @spec thumbprint(t() | JOSE.JWK.t() | map()) :: binary()
  def thumbprint(%__MODULE__{jwk: %JOSE.JWK{} = jwk}), do: jose_thumbprint!(jwk)
  def thumbprint(%JOSE.JWK{} = jwk), do: jose_thumbprint!(jwk)

  def thumbprint(map) when is_map(map) do
    case from_map(map) do
      {:ok, jwk} -> jose_thumbprint!(jwk)
      :error -> raise Error, reason: :invalid_key, message: "expected a valid JWK map"
    end
  end

  def thumbprint(_other) do
    raise Error, reason: :invalid_key, message: "expected ReqDPoP.Key, JOSE.JWK, or JWK map"
  end

  @doc false
  def alg_name(:es256), do: "ES256"
  def alg_name(:rs256), do: "RS256"

  def alg_name(alg) do
    raise Error,
      reason: {:unsupported_alg, alg},
      message: "unsupported DPoP signing algorithm #{inspect(alg)}"
  end

  defp from_jwk!(%JOSE.JWK{} = jwk) do
    alg = jose_call!(fn -> jwk |> JOSE.JWK.to_map() |> elem(1) end) |> validate!()
    # The proof header is built from this map on every request; fail here,
    # with a clean error, rather than inside JOSE with key material in the
    # stack trace.
    _thumbprint_map = jose_call!(fn -> JOSE.JWK.to_thumbprint_map(jwk) end)
    %__MODULE__{jwk: jwk, alg: alg}
  end

  defp validate!(%{"kty" => "EC", "crv" => "P-256"} = map) do
    check!(
      coordinate?(map["x"]) and coordinate?(map["y"]),
      "P-256 key needs 32-byte x and y coordinates"
    )

    check!(coordinate?(map["d"]), "expected a private key: P-256 key needs a 32-byte d")
    :es256
  end

  defp validate!(%{"kty" => "RSA"} = map) do
    bits = modulus_bits(map["n"])
    check!(is_integer(bits) and is_binary(map["e"]), "RSA key needs n and e")
    check!(is_binary(map["d"]), "expected a private key: RSA key needs d")

    if bits < @min_rsa_bits do
      raise Error,
        reason: :unsupported_key,
        message: "RSA keys must be at least #{@min_rsa_bits} bits (RFC 7518 section 3.3)"
    end

    :rs256
  end

  defp validate!(_map) do
    raise Error,
      reason: :unsupported_key,
      message: "unsupported DPoP key; use a P-256 EC key or an RSA key"
  end

  defp check!(true, _message), do: :ok
  defp check!(false, message), do: raise(Error, reason: :invalid_key, message: message)

  defp coordinate?(value) when is_binary(value) do
    match?({:ok, <<_::256>>}, Base.url_decode64(value, padding: false))
  end

  defp coordinate?(_value), do: false

  defp modulus_bits(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} when bytes != "" ->
        bytes |> :binary.decode_unsigned() |> Integer.digits(2) |> length()

      _other ->
        nil
    end
  end

  defp modulus_bits(_value), do: nil

  defp from_map(map), do: safe(fn -> JOSE.JWK.from_map(map) end)

  defp jose_thumbprint!(jwk), do: jose_call!(fn -> JOSE.JWK.thumbprint(jwk) end)

  defp jose_call!(fun) do
    case safe(fun) do
      {:ok, value} -> value
      :error -> raise Error, reason: :invalid_key, message: "JOSE could not process the key"
    end
  end

  defp safe(fun) do
    {:ok, fun.()}
  rescue
    _error -> :error
  end
end
