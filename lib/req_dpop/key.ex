defmodule ReqDPoP.Key do
  @moduledoc """
  Helpers for DPoP signing keys.

  Production clients should persist their DPoP key when they need stable
  sender binding across process restarts.
  """

  alias ReqDPoP.Error

  @type alg :: :es256 | :rs256
  @type t :: %__MODULE__{jwk: JOSE.JWK.t(), alg: alg() | nil}

  defstruct [:jwk, :alg]

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
  """
  @spec load!(t() | JOSE.JWK.t() | map()) :: t()
  def load!(%__MODULE__{} = key), do: key
  def load!(%JOSE.JWK{} = jwk), do: %__MODULE__{jwk: jwk}
  def load!(map) when is_map(map), do: %__MODULE__{jwk: JOSE.JWK.from_map(map)}

  def load!(other) do
    raise Error,
      reason: {:invalid_key, other},
      message: "expected ReqDPoP.Key, JOSE.JWK, or JWK map"
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
  """
  @spec public_jwk(t()) :: map()
  def public_jwk(%__MODULE__{jwk: jwk}) do
    jwk
    |> JOSE.JWK.to_public_map()
    |> elem(1)
  end

  @doc """
  Returns the RFC 7638 SHA-256 JWK thumbprint, base64url unpadded.
  """
  @spec thumbprint(t() | JOSE.JWK.t() | map()) :: binary()
  def thumbprint(key) do
    key
    |> load!()
    |> jose_jwk()
    |> JOSE.JWK.thumbprint()
  end

  @doc false
  def alg_name(:es256), do: "ES256"
  def alg_name(:rs256), do: "RS256"

  def alg_name(alg) do
    raise Error,
      reason: {:unsupported_alg, alg},
      message: "unsupported DPoP signing algorithm #{inspect(alg)}"
  end
end
